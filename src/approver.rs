//! `sudo-agent approve`: answers a running agent's approval requests at this
//! terminal, as a client of its `control.sock` (protocol in [`approve`]).
//!
//! One connection waits for events again and again, and each answer goes
//! over a connection of its own. When the agent goes away (restarted, the
//! desktop session logged out), the client says so and attaches again once
//! the agent is back.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Request, Response};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::agent::sanitize;
use crate::approve::{self, Event, Reply};
use crate::keys;
use crate::prompt::Prompter;

/// The approval timeout for the client's terminal prompt: none, in effect.
/// The agent withdraws a request (and with it the prompt) when it times out,
/// and a request can't stay open longer than this (the protocol sends its
/// time left as `uint32` seconds).
pub const NO_TIMEOUT: Duration = Duration::from_secs(u32::MAX as u64);

/// How often to try reaching the agent again after it went away.
const RECONNECT_EVERY: Duration = Duration::from_secs(1);

/// How long to wait for the agent to take an answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Shows the requests of the agent on `path` (its `control.sock`) with
/// `prompter`, one at a time, and sends the answers, until `shutdown`
/// resolves. Fails if the agent can't be reached at first, or refuses.
pub async fn attend(
    path: PathBuf,
    prompter: Arc<dyn Prompter>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let mut client = Attending {
        events: Events::connect(&path).await.map_err(|e| {
            let message = format!("no sudo-agent answering on {}: {e}", path.display());
            io::Error::new(e.kind(), message)
        })?,
        path,
        prompter,
        queued: VecDeque::new(),
        asking: None,
        lost: HashSet::new(),
    };
    let shutdown = std::pin::pin!(shutdown);
    client.run(shutdown).await
}

struct Attending {
    path: PathBuf,
    prompter: Arc<dyn Prompter>,
    events: Events,
    /// Requests not shown yet, oldest first, with their deadline on the
    /// [`keys::now`] clock.
    queued: VecDeque<(u64, Duration, String)>,
    /// The request on the terminal.
    asking: Option<Asking>,
    /// Requests answered here whose answer didn't decide them: their
    /// withdrawal says what did.
    lost: HashSet<u64>,
}

/// A prompt open for request `id`.
struct Asking {
    id: u64,
    /// Withdraws the prompt.
    withdraw: CancellationToken,
    prompt: Pin<Box<dyn Future<Output = io::Result<bool>> + Send>>,
}

impl Asking {
    /// Withdraws the prompt, returning once it has ended its line.
    async fn withdraw(mut self) {
        self.withdraw.cancel();
        let _ = self.prompt.as_mut().await;
    }
}

/// How serving one connection to the agent ended.
enum Ended {
    Shutdown,
    /// The agent went away.
    Lost,
}

impl Attending {
    async fn run(&mut self, mut shutdown: Pin<&mut impl Future<Output = ()>>) -> io::Result<()> {
        log!(
            "Waiting for approval requests from {}; Ctrl-C quits",
            self.path.display()
        );
        loop {
            if let Ended::Shutdown = self.serve(shutdown.as_mut()).await? {
                return Ok(());
            }
            log!("sudo-agent went away; waiting for it to start again (Ctrl-C quits)");
            self.events = tokio::select! {
                events = reconnect(&self.path) => events,
                () = shutdown.as_mut() => return Ok(()),
            };
            log!("sudo-agent is back; waiting for approval requests");
        }
    }

    /// Serves the current connection until it ends.
    async fn serve(
        &mut self,
        mut shutdown: Pin<&mut impl Future<Output = ()>>,
    ) -> io::Result<Ended> {
        loop {
            if self.asking.is_none()
                && let Some((id, deadline, message)) = self.queued.pop_front()
            {
                self.asking = Some(self.ask(id, deadline, &message));
            }
            tokio::select! {
                () = shutdown.as_mut() => {
                    self.forget().await;
                    return Ok(Ended::Shutdown);
                }
                event = self.events.next() => match event {
                    Ok(event) => self.on_event(event).await,
                    Err(Lost::Gone) => {
                        self.forget().await;
                        return Ok(Ended::Lost);
                    }
                    Err(Lost::Failed(e)) => {
                        self.forget().await;
                        return Err(e);
                    }
                },
                answer = prompt(&mut self.asking) => {
                    let id = self.asking.take().map_or(0, |asking| asking.id);
                    match answer {
                        Ok(approved) => self.answer(id, approved).await,
                        Err(e) => log!("No answer: {e}"),
                    }
                }
            }
        }
    }

    /// Opens the prompt for a request.
    fn ask(&self, id: u64, deadline: Duration, message: &str) -> Asking {
        // Sanitized here too, line by line: the lines are the agent's.
        let lines: Vec<String> = message.split('\n').map(sanitize).collect();
        // Rounded up, as the agent sends it.
        let left = deadline.saturating_sub(keys::now());
        let left = left.as_secs() + u64::from(left.subsec_nanos() > 0);
        let closes_in = keys::format_remaining(Duration::from_secs(left));
        let message = format!("{} (closes in {closes_in})", lines.join("\n"));
        let withdraw = CancellationToken::new();
        let prompter = Arc::clone(&self.prompter);
        let cancel = withdraw.clone();
        let prompt = Box::pin(async move { prompter.confirm(&message, &cancel).await });
        Asking {
            id,
            withdraw,
            prompt,
        }
    }

    async fn on_event(&mut self, event: Event) {
        match event {
            Event::Pending {
                id,
                closes_in,
                message,
            } => self
                .queued
                .push_back((id, keys::now() + closes_in, message)),
            Event::Withdrawn { id, reason } => {
                let reason = sanitize(&reason);
                if let Some(asking) = self.asking.take_if(|asking| asking.id == id) {
                    asking.withdraw().await;
                    log!("Withdrawn: {reason}");
                } else if self.lost.remove(&id) {
                    log!("Too late: {reason}");
                } else {
                    // Never shown, or decided by our answer.
                    self.queued.retain(|(queued, ..)| *queued != id);
                }
            }
        }
    }

    /// Sends the answer to request `id`, and says whether it decided it.
    async fn answer(&mut self, id: u64, approved: bool) {
        let answered = tokio::time::timeout(ANSWER_TIMEOUT, send_answer(&self.path, id, approved));
        match answered.await {
            Ok(Ok(true)) => log!("{}", if approved { "Allowed" } else { "Denied" }),
            // The withdrawal that follows says why.
            Ok(Ok(false)) => {
                self.lost.insert(id);
            }
            Ok(Err(e)) => log!("Couldn't send the answer: {e}"),
            Err(_) => log!("Couldn't send the answer: sudo-agent didn't take it"),
        }
    }

    /// Withdraws the open prompt, if any, and forgets every request: they
    /// belong to a connection that is ending.
    async fn forget(&mut self) {
        if let Some(asking) = self.asking.take() {
            asking.withdraw().await;
        }
        self.queued.clear();
        self.lost.clear();
    }
}

/// The open prompt's answer; never resolves while there is none.
async fn prompt(asking: &mut Option<Asking>) -> io::Result<bool> {
    match asking {
        Some(asking) => asking.prompt.as_mut().await,
        None => std::future::pending().await,
    }
}

/// Connects to the agent on `path` again once it answers.
async fn reconnect(path: &Path) -> Events {
    loop {
        tokio::time::sleep(RECONNECT_EVERY).await;
        if let Ok(events) = Events::connect(path).await {
            return events;
        }
    }
}

/// Answers request `id` over a connection of its own. `Ok(false)`: the
/// answer didn't decide the request.
async fn send_answer(path: &Path, id: u64, approved: bool) -> io::Result<bool> {
    let mut client = Client::new(UnixStream::connect(path).await?);
    let reply = Extension::new_message(Reply { id, approved }).map_err(io::Error::other)?;
    match client.handle(Request::Extension(reply)).await {
        Ok(Response::Success) => Ok(true),
        Ok(Response::Failure) => Ok(false),
        Ok(other) => Err(io::Error::other(format!("unexpected reply {other:?}"))),
        Err(e) => Err(io::Error::other(e)),
    }
}

/// Why a connection's events ended.
enum Lost {
    /// The agent went away.
    Gone,
    /// The agent refused, or sent something this client doesn't know;
    /// attaching again won't help.
    Failed(io::Error),
}

/// The events of one connection to the agent, read in the background (a
/// wait can't be interrupted without losing its reply).
struct Events {
    received: mpsc::Receiver<Result<Event, Lost>>,
    reader: JoinHandle<()>,
}

impl Events {
    async fn connect(path: &Path) -> io::Result<Self> {
        let mut client = Client::new(UnixStream::connect(path).await?);
        let (send, received) = mpsc::channel(16);
        let path = path.to_owned();
        let reader = tokio::spawn(async move {
            loop {
                let event = next_event(&mut client, &path).await;
                let last = event.is_err();
                if send.send(event).await.is_err() || last {
                    return;
                }
            }
        });
        Ok(Self { received, reader })
    }

    async fn next(&mut self) -> Result<Event, Lost> {
        self.received.recv().await.unwrap_or(Err(Lost::Gone))
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        // Hangs up, which detaches this client.
        self.reader.abort();
    }
}

async fn next_event(client: &mut Client<UnixStream>, path: &Path) -> Result<Event, Lost> {
    let wait = Extension {
        name: approve::WAIT.into(),
        details: Vec::new().into(),
    };
    let failed = |message: String| {
        Err(Lost::Failed(io::Error::new(
            ErrorKind::InvalidData,
            message,
        )))
    };
    match client.handle(Request::Extension(wait)).await {
        Ok(Response::ExtensionResponse(reply)) => match reply.parse_message::<Event>() {
            Ok(Some(event)) => Ok(event),
            Ok(None) => failed(format!("unexpected reply {:?}", sanitize(&reply.name))),
            Err(e) => failed(format!("unexpected reply: {e}")),
        },
        // An older version without approvals, or the connection was refused
        // (the agent logs why).
        Ok(Response::Failure) => Err(Lost::Failed(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "sudo-agent on {} refused to send approval requests (too old for \
                 sudo-agent approve? see its log)",
                path.display()
            ),
        ))),
        Ok(other) => failed(format!("unexpected reply {other:?}")),
        Err(_) => Err(Lost::Gone),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::testing::ScriptedPrompter;
    use async_trait::async_trait;
    use ssh_agent_lib::agent::listen;
    use ssh_agent_lib::error::AgentError;
    use tokio::sync::Mutex;

    /// An agent whose waits return what the test sends, and which refuses
    /// every answer (as if each came too late), passing it to the test.
    #[derive(Clone)]
    struct Scripted {
        events: Arc<Mutex<mpsc::Receiver<Extension>>>,
        answers: mpsc::Sender<Reply>,
    }

    #[async_trait]
    impl Session for Scripted {
        async fn extension(
            &mut self,
            extension: Extension,
        ) -> Result<Option<Extension>, AgentError> {
            if extension.name == approve::ANSWER {
                let reply = extension.parse_message::<Reply>().unwrap().unwrap();
                self.answers.send(reply).await.unwrap();
                return Err(AgentError::Failure);
            }
            match self.events.lock().await.recv().await {
                Some(event) => Ok(Some(event)),
                None => std::future::pending().await,
            }
        }
    }

    async fn within<T>(future: impl Future<Output = T>) -> T {
        let limit = Duration::from_secs(5);
        tokio::time::timeout(limit, future)
            .await
            .expect("timed out")
    }

    #[tokio::test]
    async fn an_answer_too_late_and_an_unknown_reply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let (send_event, events) = mpsc::channel(4);
        let (answers, mut answered) = mpsc::channel(4);
        let agent = Scripted {
            events: Arc::new(Mutex::new(events)),
            answers,
        };
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let _serving = tokio::spawn(listen(listener, agent));
        let prompter = Arc::new(ScriptedPrompter::with_confirms([true]));
        let shutdown = std::future::pending();
        let attending = tokio::spawn(attend(path, prompter.clone(), shutdown));

        let pending = Event::Pending {
            id: 7,
            closes_in: Duration::from_secs(60),
            message: "Allow?\u{1b}[2J".into(),
        };
        send_event
            .send(Extension::new_message(pending).unwrap())
            .await
            .unwrap();
        let reply = within(answered.recv()).await.unwrap();
        assert_eq!(
            reply,
            Reply {
                id: 7,
                approved: true
            }
        );
        // Shown sanitized.
        assert_eq!(prompter.asked(), ["Allow?\\u{1b}[2J (closes in 1m00s)"]);
        let withdrawn = Event::Withdrawn {
            id: 7,
            reason: "answered elsewhere".into(),
        };
        send_event
            .send(Extension::new_message(withdrawn).unwrap())
            .await
            .unwrap();

        // Not an approval event: a different version, so it gives up.
        let unknown = Extension {
            name: "other@example.com".into(),
            details: Vec::new().into(),
        };
        send_event.send(unknown).await.unwrap();
        let e = within(attending).await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
    }
}
