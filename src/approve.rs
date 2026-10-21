//! `sudo-agent approve` clients as one approval backend: every attached client
//! is shown each request, and the first answer from any of them counts.
//!
//! Clients talk to `control.sock` with two vendor extensions:
//!
//! - [`WAIT`] (no details) returns the client's next [`Event`], waiting for
//!   one if there is none yet. The first wait attaches the connection: from
//!   then on, events for it are queued until it asks for them, and it counts
//!   as attached until it closes. A client keeps this connection open and
//!   waits on it again and again.
//! - [`ANSWER`] ([`Reply`]) answers a pending request by id. It goes over a
//!   second connection, as the first is busy waiting. `Success` means the
//!   answer was delivered, `Failure` that the request is no longer pending.
//!   A delivered answer still loses if the request ends at the same moment
//!   (another backend answered, it timed out); the withdrawal event that
//!   follows says what decided it.
//!
//! Request ids start at a random value in each daemon, so an answer meant
//! for a request of an earlier daemon (one that restarted while a client
//! showed its request) can't answer a new request that got the same number.
//!
//! Only `control.sock` serves them, with its protections; `agent.sock`, the
//! forwarded one, refuses them like any other extension.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use async_trait::async_trait;
use ssh_agent_lib::proto::ProtoError;
use ssh_agent_lib::proto::extension::MessageExtension;
use ssh_agent_lib::ssh_encoding::{self, CheckedSum, Decode, Encode, Reader, Writer};
use ssh_key::rand_core::{OsRng, RngCore};
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::agent::sanitize;
use crate::keys;
use crate::prompt::Prompter;

/// Waits for the next event; the reply is an [`Event`] under the same name.
pub const WAIT: &str = "approve-wait@sudo-agent.juusolatva.github.io";

/// Answers a pending request: a [`Reply`].
pub const ANSWER: &str = "approve-answer@sudo-agent.juusolatva.github.io";

/// Why a request was withdrawn from clients when it wasn't answered by one
/// of them, or timed out.
pub const WITHDRAWN: &str = "answered elsewhere, or no longer needed";

/// How long a request still waits for a client after the last one detached,
/// in case one attaches again (e.g. restarted). Waiting the whole timeout
/// would hang `sudo` with nobody left to answer.
const GRACE: Duration = Duration::from_secs(5);

/// Every attached `sudo-agent approve` client, as one approval backend.
/// Available while at least one is attached.
pub struct ApproveClients {
    /// How long a request waits for an answer from a client.
    timeout: Duration,
    /// [`GRACE`], shorter in tests.
    grace: Duration,
    state: Mutex<State>,
    /// Notified whenever a client detaches (its queue is dropped).
    detached: Arc<Notify>,
}

struct State {
    last_id: u64,
    /// Each attached connection's queue; a connection that closes drops its
    /// queue, which detaches it.
    clients: Vec<Weak<Events>>,
    /// Requests out to clients, oldest first: a client that attaches is
    /// shown these.
    open: Vec<Open>,
}

struct Open {
    id: u64,
    message: String,
    /// On the [`keys::now`] clock.
    deadline: Duration,
    /// Taken by the first answer, which says who gave it.
    answer: Option<oneshot::Sender<(bool, String)>>,
}

impl ApproveClients {
    pub fn new(timeout: Duration) -> Self {
        let state = State {
            last_id: OsRng.next_u64(),
            clients: Vec::new(),
            open: Vec::new(),
        };
        Self {
            timeout,
            grace: GRACE,
            state: Mutex::new(state),
            detached: Arc::default(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Attaches a client: returns its queue, already holding the requests
    /// that are open right now. It stays attached while the queue is kept.
    pub fn attach(&self) -> Arc<Events> {
        let events = Arc::new(Events {
            queue: Mutex::default(),
            ready: Notify::new(),
            detached: Arc::clone(&self.detached),
        });
        let mut state = self.state();
        state.clients.retain(|client| client.strong_count() > 0);
        for open in &state.open {
            events.push(Queued::Pending {
                id: open.id,
                message: open.message.clone(),
                deadline: open.deadline,
            });
        }
        state.clients.push(Arc::downgrade(&events));
        events
    }

    /// Answers request `id` on behalf of `from` (the answering client).
    /// Returns whether the answer was delivered: `false` if the request isn't
    /// pending any more (answered, timed out, withdrawn) or never was.
    pub fn answer(&self, id: u64, approved: bool, from: &str) -> bool {
        let now = keys::now();
        let answer = self
            .state()
            .open
            .iter_mut()
            .find(|open| open.id == id && now < open.deadline)
            .and_then(|open| open.answer.take());
        answer.is_some_and(|answer| answer.send((approved, from.to_owned())).is_ok())
    }

    /// Resolves once no client has been attached for [`GRACE`] (`grace`)
    /// since the last one detached.
    async fn abandoned(&self) {
        loop {
            // Registered before checking, so a detach in between still wakes
            // it.
            let detached = self.detached.notified();
            tokio::pin!(detached);
            detached.as_mut().enable();
            if self.available() {
                detached.await;
                continue;
            }
            // A client that attaches and detaches again meanwhile starts the
            // grace period over.
            tokio::select! {
                () = tokio::time::sleep(self.grace) => {}
                () = &mut detached => continue,
            }
            if !self.available() {
                return;
            }
        }
    }

    /// Opens a request: queues it for every attached client. The returned
    /// guard withdraws it again.
    fn open(
        &self,
        message: &str,
        deadline: Duration,
    ) -> (Opened<'_>, oneshot::Receiver<(bool, String)>) {
        let (answer, answered) = oneshot::channel();
        let mut state = self.state();
        state.last_id = state.last_id.wrapping_add(1);
        let id = state.last_id;
        state.open.push(Open {
            id,
            message: message.to_owned(),
            deadline,
            answer: Some(answer),
        });
        broadcast(
            &mut state,
            &Queued::Pending {
                id,
                message: message.to_owned(),
                deadline,
            },
        );
        let opened = Opened {
            clients: self,
            id,
            reason: WITHDRAWN.to_owned(),
        };
        (opened, answered)
    }

    /// Closes request `id`: no longer answerable, and withdrawn from every
    /// client, which is told `reason`.
    fn close(&self, id: u64, reason: &str) {
        let mut state = self.state();
        state.open.retain(|open| open.id != id);
        let withdrawn = Queued::Withdrawn {
            id,
            reason: reason.to_owned(),
        };
        broadcast(&mut state, &withdrawn);
    }
}

#[cfg(test)]
impl ApproveClients {
    pub fn with_grace(self, grace: Duration) -> Self {
        Self { grace, ..self }
    }

    /// How many clients are attached.
    pub fn attached(&self) -> usize {
        let state = self.state();
        let attached = state.clients.iter().filter(|c| c.strong_count() > 0);
        attached.count()
    }
}

/// Queues `event` for every attached client, forgetting the detached ones.
fn broadcast(state: &mut State, event: &Queued) {
    state.clients.retain(|client| match client.upgrade() {
        Some(events) => {
            events.push(event.clone());
            true
        }
        None => false,
    });
}

/// A request open to clients; withdraws it when dropped, with `reason`.
struct Opened<'a> {
    clients: &'a ApproveClients,
    id: u64,
    reason: String,
}

impl Opened<'_> {
    fn close(mut self, reason: &str) {
        reason.clone_into(&mut self.reason);
    }
}

impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.clients.close(self.id, &self.reason);
    }
}

#[async_trait]
impl Prompter for ApproveClients {
    async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
        Err(io::Error::other(
            "sudo-agent approve only answers approvals",
        ))
    }

    /// Asks the attached clients. If they all detach meanwhile, it waits
    /// [`GRACE`] for one to attach again, then gives up.
    async fn confirm(&self, message: &str, cancel: &CancellationToken) -> io::Result<bool> {
        if cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        let deadline = keys::now() + self.timeout;
        let (opened, answered) = self.open(message, deadline);
        let result = tokio::select! {
            // An answer that comes as the request ends doesn't count.
            biased;
            () = cancel.cancelled() => Err(io::Error::other("cancelled")),
            () = until(deadline) => Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("no answer within {}", keys::format_duration(self.timeout)),
            )),
            () = self.abandoned() => Err(io::Error::new(
                ErrorKind::NotConnected,
                "every sudo-agent approve detached",
            )),
            answer = answered => answer.map_err(|_| io::Error::other("answer lost")),
        };
        let reason = match &result {
            Ok((approved, from)) => {
                // Only an answer that is used is logged, before the
                // request's outcome.
                let verdict = if *approved { "Allowed" } else { "Denied" };
                log!("{verdict} by approve client {from}");
                format!("answered by approve client {from}")
            }
            Err(e) if e.kind() == ErrorKind::TimedOut => e.to_string(),
            Err(_) => WITHDRAWN.to_owned(),
        };
        opened.close(&reason);
        result.map(|(approved, _)| approved)
    }

    fn available(&self) -> bool {
        self.state()
            .clients
            .iter()
            .any(|client| client.strong_count() > 0)
    }
}

/// Resolves once `deadline` on the [`keys::now`] clock has passed.
async fn until(deadline: Duration) {
    loop {
        let now = keys::now();
        if now >= deadline {
            return;
        }
        // `sleep` runs on CLOCK_MONOTONIC, which stops during suspend; see
        // `SudoAgent::key_gone`.
        tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
    }
}

/// An event as queued for a client.
#[derive(Clone, Debug)]
enum Queued {
    Pending {
        id: u64,
        message: String,
        deadline: Duration,
    },
    Withdrawn {
        id: u64,
        reason: String,
    },
}

/// One attached client's events, in order, until it asks for them. Dropping
/// it detaches the client.
pub struct Events {
    queue: Mutex<VecDeque<Queued>>,
    ready: Notify,
    /// [`ApproveClients::detached`].
    detached: Arc<Notify>,
}

impl Drop for Events {
    fn drop(&mut self) {
        // Its `Weak` no longer upgrades, so waiters see it gone.
        self.detached.notify_waiters();
    }
}

impl Events {
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Queued>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `event`. A request withdrawn before the client was even told
    /// about it is dropped from the queue instead, so the queue stays short
    /// however long the client goes without asking: at most the requests
    /// open now plus one withdrawal for each it was told about.
    fn push(&self, event: Queued) {
        let mut queue = self.queue();
        if let Queued::Withdrawn { id, .. } = &event {
            let before = queue.len();
            queue.retain(|queued| !matches!(queued, Queued::Pending { id: p, .. } if p == id));
            if queue.len() != before {
                return;
            }
        }
        queue.push_back(event);
        drop(queue);
        self.ready.notify_one();
    }

    /// The next event, once there is one. Cancel safe: an event is taken
    /// from the queue only when it is returned.
    pub async fn next(&self) -> Event {
        loop {
            if let Some(event) = self.queue().pop_front() {
                return match event {
                    Queued::Pending {
                        id,
                        message,
                        deadline,
                    } => Event::Pending {
                        id,
                        closes_in: deadline.saturating_sub(keys::now()),
                        message,
                    },
                    Queued::Withdrawn { id, reason } => Event::Withdrawn { id, reason },
                };
            }
            // `notify_one` keeps a permit when nobody waits, so a push
            // between the check and here isn't missed.
            self.ready.notified().await;
        }
    }
}

/// What a [`WAIT`] returns.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// A request to answer: `string "pending"`, `uint64 id`, `uint32` seconds
    /// until it closes, `string message`.
    Pending {
        id: u64,
        closes_in: Duration,
        message: String,
    },
    /// A request no longer to answer: `string "withdrawn"`, `uint64 id`,
    /// `string reason`.
    Withdrawn { id: u64, reason: String },
}

impl MessageExtension for Event {
    const NAME: &'static str = WAIT;
}

const PENDING: &str = "pending";
const WITHDRAWN_EVENT: &str = "withdrawn";

impl Encode for Event {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        match self {
            Event::Pending { message, .. } => [
                PENDING.encoded_len()?,
                8,
                4,
                message.as_str().encoded_len()?,
            ]
            .checked_sum(),
            Event::Withdrawn { reason, .. } => [
                WITHDRAWN_EVENT.encoded_len()?,
                8,
                reason.as_str().encoded_len()?,
            ]
            .checked_sum(),
        }
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        match self {
            Event::Pending {
                id,
                closes_in,
                message,
            } => {
                PENDING.encode(writer)?;
                id.encode(writer)?;
                // Rounded up: a request about to close still has a second.
                let seconds = closes_in.as_secs() + u64::from(closes_in.subsec_nanos() > 0);
                u32::try_from(seconds).unwrap_or(u32::MAX).encode(writer)?;
                message.as_str().encode(writer)
            }
            Event::Withdrawn { id, reason } => {
                WITHDRAWN_EVENT.encode(writer)?;
                id.encode(writer)?;
                reason.as_str().encode(writer)
            }
        }
    }
}

impl Decode for Event {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let kind = String::decode(reader)?;
        let id = u64::decode(reader)?;
        let event = match kind.as_str() {
            PENDING => Event::Pending {
                id,
                closes_in: Duration::from_secs(u32::decode(reader)?.into()),
                message: String::decode(reader)?,
            },
            WITHDRAWN_EVENT => Event::Withdrawn {
                id,
                reason: String::decode(reader)?,
            },
            _ => {
                return Err(invalid(format!(
                    "unknown approve event {:?} (a different sudo-agent version?)",
                    sanitize(&kind)
                )));
            }
        };
        finished(reader)?;
        Ok(event)
    }
}

fn invalid(message: String) -> ProtoError {
    io::Error::new(ErrorKind::InvalidData, message).into()
}

/// Fails if anything is left after a message: it isn't the message we know
/// (malformed, or a different format), and taking its known part as is could
/// approve something.
fn finished(reader: &impl Reader) -> Result<(), ProtoError> {
    match reader.is_finished() {
        true => Ok(()),
        false => Err(invalid(format!(
            "{} unexpected bytes at the end of an approve message",
            reader.remaining_len()
        ))),
    }
}

/// An [`ANSWER`]: `uint64 id`, `byte approved` (1 or 0).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reply {
    pub id: u64,
    pub approved: bool,
}

impl MessageExtension for Reply {
    const NAME: &'static str = ANSWER;
}

impl Encode for Reply {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        Ok(8 + 1)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), ssh_encoding::Error> {
        self.id.encode(writer)?;
        u8::from(self.approved).encode(writer)
    }
}

impl Decode for Reply {
    type Error = ProtoError;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let id = u64::decode(reader)?;
        let approved = match u8::decode(reader)? {
            0 => false,
            1 => true,
            other => return Err(invalid(format!("bad approve answer {other}"))),
        };
        finished(reader)?;
        Ok(Reply { id, approved })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::proto::Extension;
    use std::future::Future;

    const LONG: Duration = Duration::from_secs(60);

    /// The next event, or `None` if none is queued.
    fn queued(events: &Events) -> Option<Event> {
        let next = events.next();
        tokio::pin!(next);
        let waker = std::task::Waker::noop();
        match next
            .as_mut()
            .poll(&mut std::task::Context::from_waker(waker))
        {
            std::task::Poll::Ready(event) => Some(event),
            std::task::Poll::Pending => None,
        }
    }

    fn pending_id(event: Option<Event>) -> u64 {
        match event {
            Some(Event::Pending { id, .. }) => id,
            other => panic!("expected a pending request, got {other:?}"),
        }
    }

    fn withdrawn(event: Option<Event>) -> (u64, String) {
        match event {
            Some(Event::Withdrawn { id, reason }) => (id, reason),
            other => panic!("expected a withdrawal, got {other:?}"),
        }
    }

    /// Starts asking `clients` in the background.
    fn ask(
        clients: &Arc<ApproveClients>,
        cancel: &CancellationToken,
    ) -> tokio::task::JoinHandle<io::Result<bool>> {
        let (clients, cancel) = (Arc::clone(clients), cancel.clone());
        tokio::spawn(async move { clients.confirm("Allow?", &cancel).await })
    }

    /// `future`'s result, failing the test rather than hanging it if it
    /// doesn't come.
    async fn within<T>(future: impl Future<Output = T>) -> T {
        let limit = Duration::from_secs(5);
        tokio::time::timeout(limit, future)
            .await
            .expect("timed out")
    }

    async fn until_open(clients: &ApproveClients, count: usize) {
        within(async {
            while clients.state().open.len() < count {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
    }

    #[test]
    fn available_only_while_a_client_is_attached() {
        let clients = ApproveClients::new(LONG);
        assert!(!clients.available());
        let one = clients.attach();
        let two = clients.attach();
        assert!(clients.available());
        drop(one);
        assert!(clients.available());
        drop(two);
        assert!(!clients.available());
    }

    #[tokio::test]
    async fn every_client_is_shown_the_request_and_the_first_answer_counts() {
        let clients = Arc::new(ApproveClients::new(LONG));
        let (one, two) = (clients.attach(), clients.attach());
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;

        let id = pending_id(queued(&one));
        let Some(Event::Pending {
            id: same,
            closes_in,
            message,
        }) = queued(&two)
        else {
            panic!("the second client wasn't shown the request");
        };
        assert_eq!(same, id);
        assert_eq!(message, "Allow?");
        assert!(closes_in > LONG - Duration::from_secs(5) && closes_in <= LONG);

        assert!(clients.answer(id, false, "pid 7"));
        assert!(!within(asking).await.unwrap().unwrap());
        // Too late: already answered.
        assert!(!clients.answer(id, true, "pid 8"));
        for client in [&one, &two] {
            let reason = "answered by approve client pid 7".to_owned();
            assert_eq!(withdrawn(queued(client)), (id, reason));
            assert_eq!(queued(client), None);
        }
    }

    #[tokio::test]
    async fn a_late_client_is_shown_open_requests() {
        let clients = Arc::new(ApproveClients::new(LONG));
        let _early = clients.attach();
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;

        let late = clients.attach();
        let id = pending_id(queued(&late));
        assert!(clients.answer(id, true, "test"));
        assert!(within(asking).await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn withdrawal_reaches_clients_and_refuses_answers() {
        let clients = Arc::new(ApproveClients::new(LONG));
        let client = clients.attach();
        let cancel = CancellationToken::new();
        let asking = ask(&clients, &cancel);
        until_open(&clients, 1).await;
        let id = pending_id(queued(&client));

        cancel.cancel();
        let e = within(asking).await.unwrap().unwrap_err();
        assert_ne!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(withdrawn(queued(&client)), (id, WITHDRAWN.into()));
        assert!(!clients.answer(id, true, "test"));
        assert!(clients.state().open.is_empty());
    }

    #[tokio::test]
    async fn times_out_and_says_so() {
        let clients = Arc::new(ApproveClients::new(Duration::from_millis(50)));
        let client = clients.attach();
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;
        let id = pending_id(queued(&client));
        let e = within(asking).await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(withdrawn(queued(&client)), (id, e.to_string()));
    }

    #[tokio::test]
    async fn a_client_attaching_again_within_the_grace_period_can_answer() {
        let clients = Arc::new(ApproveClients::new(LONG));
        let first = clients.attach();
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;
        drop(first);
        assert!(!clients.available());

        let again = clients.attach();
        let id = pending_id(queued(&again));
        assert!(clients.answer(id, true, "test"));
        assert!(within(asking).await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn gives_up_soon_after_every_client_detaches() {
        let grace = Duration::from_millis(100);
        let clients = Arc::new(ApproveClients::new(LONG).with_grace(grace));
        let (one, two) = (clients.attach(), clients.attach());
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;
        drop(one);
        // One is still there.
        tokio::time::sleep(grace * 2).await;
        assert!(!asking.is_finished());

        let started = std::time::Instant::now();
        drop(two);
        let e = within(asking).await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotConnected);
        assert!(started.elapsed() >= grace);
        assert!(clients.state().open.is_empty());
    }

    /// From the last detach, not the first: a restarted client that goes
    /// again doesn't cut the next one's time short.
    #[tokio::test]
    async fn the_grace_period_starts_over_with_each_detach() {
        let grace = Duration::from_millis(200);
        let clients = Arc::new(ApproveClients::new(LONG).with_grace(grace));
        let first = clients.attach();
        let asking = ask(&clients, &CancellationToken::new());
        until_open(&clients, 1).await;
        drop(first);
        tokio::time::sleep(grace / 2).await;
        let again = clients.attach();
        pending_id(queued(&again));
        tokio::time::sleep(grace / 4).await;

        let last_detach = std::time::Instant::now();
        drop(again);
        let e = within(asking).await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotConnected);
        let waited = last_detach.elapsed();
        assert!(waited >= grace, "gave up {waited:?} after the last detach");
    }

    /// The request ended (here: withdrawn) as the answer came; it doesn't
    /// count.
    #[tokio::test]
    async fn an_answer_as_the_request_ends_does_not_count() {
        let clients = Arc::new(ApproveClients::new(LONG));
        let _client = clients.attach();
        let cancel = CancellationToken::new();
        let asking = ask(&clients, &cancel);
        until_open(&clients, 1).await;
        let id = clients.state().open[0].id;
        cancel.cancel();
        // Delivered or not (if `confirm` has already closed the request), it
        // loses.
        clients.answer(id, true, "test");
        let result = within(asking).await.unwrap();
        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn answers_past_the_deadline_are_refused() {
        let clients = ApproveClients::new(LONG);
        let (opened, _answered) = clients.open("Allow?", keys::now());
        assert!(!clients.answer(opened.id, true, "test"));
    }

    /// An answer meant for a request of a daemon that has since restarted
    /// must not answer the new daemon's request.
    #[test]
    fn request_ids_differ_between_daemons() {
        let (old, new) = (ApproveClients::new(LONG), ApproveClients::new(LONG));
        let (old_request, _) = old.open("old", keys::now() + LONG);
        let (new_request, _) = new.open("new", keys::now() + LONG);
        assert_ne!(old_request.id, new_request.id);
        assert!(!new.answer(old_request.id, true, "stale"));
    }

    #[test]
    fn unknown_ids_are_not_answered() {
        let clients = ApproveClients::new(LONG);
        assert!(!clients.answer(7, true, "test"));
    }

    #[test]
    fn a_request_withdrawn_before_it_was_shown_is_dropped_from_the_queue() {
        let clients = ApproveClients::new(LONG);
        let client = clients.attach();

        // Told about the first request, then not asking for a while.
        let (first, _answered) = clients.open("first", keys::now() + LONG);
        let first_id = first.id;
        assert_eq!(pending_id(queued(&client)), first_id);
        first.close(WITHDRAWN);
        for _ in 0..100 {
            let (opened, _answered) = clients.open("unseen", keys::now() + LONG);
            opened.close(WITHDRAWN);
        }
        // Only the withdrawal of the one it was shown is left.
        assert_eq!(client.queue().len(), 1);
        assert_eq!(withdrawn(queued(&client)).0, first_id);
        assert_eq!(queued(&client), None);
    }

    #[test]
    fn dropping_an_open_request_withdraws_it() {
        let clients = ApproveClients::new(LONG);
        let client = clients.attach();
        let (opened, _answered) = clients.open("Allow?", keys::now() + LONG);
        let id = pending_id(queued(&client));
        drop(opened);
        assert_eq!(withdrawn(queued(&client)), (id, WITHDRAWN.into()));
        assert!(!clients.answer(id, true, "test"));
    }

    #[test]
    fn events_and_replies_round_trip() {
        let events = [
            Event::Pending {
                id: 3,
                closes_in: Duration::from_secs(120),
                message: "Signature request from pid 1\nAllow?".into(),
            },
            Event::Withdrawn {
                id: u64::MAX,
                reason: WITHDRAWN.into(),
            },
        ];
        for event in events {
            let extension = Extension::new_message(event.clone()).unwrap();
            assert_eq!(extension.name, WAIT);
            assert_eq!(extension.parse_message::<Event>().unwrap(), Some(event));
        }
        for approved in [true, false] {
            let reply = Reply { id: 9, approved };
            let extension = Extension::new_message(reply).unwrap();
            assert_eq!(extension.name, ANSWER);
            assert_eq!(extension.parse_message::<Reply>().unwrap(), Some(reply));
        }
    }

    #[test]
    fn seconds_left_are_rounded_up() {
        let event = Event::Pending {
            id: 1,
            closes_in: Duration::from_millis(1500),
            message: String::new(),
        };
        let extension = Extension::new_message(event).unwrap();
        let Some(Event::Pending { closes_in, .. }) = extension.parse_message().unwrap() else {
            panic!("not a pending event");
        };
        assert_eq!(closes_in, Duration::from_secs(2));
    }

    #[test]
    fn malformed_replies_are_rejected() {
        let parse = |bytes: Vec<u8>| {
            Extension {
                name: ANSWER.into(),
                details: bytes.into(),
            }
            .parse_message::<Reply>()
        };
        let id = [0, 0, 0, 0, 0, 0, 0, 1];
        assert!(parse([&id[..], &[1]].concat()).is_ok());
        assert!(parse([&id[..], &[2]].concat()).is_err());
        assert!(parse(vec![0, 0]).is_err());
        // Approving, then something we don't know.
        assert!(parse([&id[..], &[1, 0xde, 0xad]].concat()).is_err());

        let mut withdrawn = Vec::new();
        Event::Withdrawn {
            id: 1,
            reason: "gone".into(),
        }
        .encode(&mut withdrawn)
        .unwrap();
        withdrawn.push(0);
        let event = Extension {
            name: WAIT.into(),
            details: withdrawn.into(),
        };
        assert!(event.parse_message::<Event>().is_err());
        let unknown = Extension {
            name: WAIT.into(),
            details: {
                let mut bytes = Vec::new();
                "later".encode(&mut bytes).unwrap();
                1u64.encode(&mut bytes).unwrap();
                bytes.into()
            },
        };
        assert!(unknown.parse_message::<Event>().is_err());
    }
}
