//! Approval routing: every available backend (the terminal, pinentry; later
//! `sudo-agent approve` clients) is asked at once, and the first answer wins.

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;

use tokio_util::sync::CancellationToken;

use crate::prompt::Prompter;

/// An approval backend and the name it's logged under.
struct Backend {
    name: &'static str,
    prompter: Arc<dyn Prompter>,
}

/// Asks every available backend at once. The first answer (approve or deny)
/// wins, and the other backends are withdrawn. A backend that gives up (times
/// out, fails) is no answer, not a denial: the request is only denied once
/// all of them have given up, or if none is available.
pub struct Router {
    backends: Vec<Backend>,
    /// Backend failures already handed out in an [`Answer`], so each is
    /// logged once rather than on every request.
    reported: Mutex<HashSet<String>>,
}

/// How a request was answered.
#[derive(Debug)]
pub struct Answer {
    pub approved: bool,
    /// The backend that answered.
    pub by: &'static str,
    /// Failures of other backends while asking (not timeouts), each one only
    /// the first time it happens.
    pub problems: Vec<String>,
}

impl Router {
    pub fn new(backends: impl IntoIterator<Item = (&'static str, Arc<dyn Prompter>)>) -> Self {
        let backends = backends
            .into_iter()
            .map(|(name, prompter)| Backend { name, prompter })
            .collect();
        Self {
            backends,
            reported: Mutex::default(),
        }
    }

    /// A router with just `prompter`, named `test`.
    #[cfg(test)]
    pub fn only(prompter: Arc<dyn Prompter>) -> Self {
        Self::new([("test", prompter)])
    }

    /// Asks for approval. `Err` means no backend answered, which callers
    /// treat as a denial.
    ///
    /// Once `cancel` fires, every backend withdraws the question; this
    /// returns only after they all have, so nothing logged afterwards lands
    /// inside a prompt.
    pub async fn ask(&self, message: &str, cancel: &CancellationToken) -> io::Result<Answer> {
        // Fires with `cancel`, or once a backend has answered.
        let withdraw = cancel.child_token();
        let mut asking: Vec<(&'static str, Asking<'_>)> = self
            .backends
            .iter()
            .filter(|backend| backend.prompter.available())
            .map(|backend| (backend.name, backend.prompter.confirm(message, &withdraw)))
            .collect();
        if asking.is_empty() {
            return Err(io::Error::other("no approval backend is available"));
        }
        let mut gave_up = Vec::new();
        while let Some((name, result)) = next_done(&mut asking).await {
            match result {
                Ok(approved) => {
                    withdraw.cancel();
                    // Returns once the others are gone, so their lines end
                    // before the log line.
                    while next_done(&mut asking).await.is_some() {}
                    return Ok(Answer {
                        approved,
                        by: name,
                        problems: self.new_problems(&gave_up),
                    });
                }
                Err(e) => gave_up.push((name, e)),
            }
        }
        Err(no_answer(gave_up))
    }

    /// The failures among `gave_up` not reported before. A timeout isn't a
    /// failure: the user just answered somewhere else. Nor is a backend left
    /// with nobody to ask (`NotConnected`: every `sudo-agent approve` went).
    fn new_problems(&self, gave_up: &[(&'static str, io::Error)]) -> Vec<String> {
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        gave_up
            .iter()
            .filter(|(_, e)| !matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::NotConnected))
            .map(|(name, e)| format!("{name}: {e}"))
            .filter(|problem| reported.insert(problem.clone()))
            .collect()
    }
}

/// One backend's open question.
type Asking<'a> = Pin<Box<dyn Future<Output = io::Result<bool>> + Send + 'a>>;

/// Waits for the next backend in `asking` to finish and removes it; `None`
/// once none is left.
async fn next_done(
    asking: &mut Vec<(&'static str, Asking<'_>)>,
) -> Option<(&'static str, io::Result<bool>)> {
    if asking.is_empty() {
        return None;
    }
    poll_fn(|cx| {
        let done = asking
            .iter_mut()
            .enumerate()
            .find_map(|(i, (_, question))| match question.as_mut().poll(cx) {
                Poll::Ready(result) => Some((i, result)),
                Poll::Pending => None,
            });
        match done {
            Some((i, result)) => Poll::Ready(Some((asking.swap_remove(i).0, result))),
            None => Poll::Pending,
        }
    })
    .await
}

/// Why no backend answered: a lone backend's own error as is (so a timeout
/// stays `ErrorKind::TimedOut`), otherwise each backend's reason.
fn no_answer(mut gave_up: Vec<(&'static str, io::Error)>) -> io::Error {
    if gave_up.len() == 1 {
        return gave_up.remove(0).1;
    }
    let kind = if gave_up.iter().all(|(_, e)| e.kind() == ErrorKind::TimedOut) {
        ErrorKind::TimedOut
    } else {
        ErrorKind::Other
    };
    let reasons: Vec<String> = gave_up
        .iter()
        .map(|(name, e)| format!("{name}: {e}"))
        .collect();
    io::Error::new(kind, reasons.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::testing::{ApprovesAfter, GivesUp, ScriptedPrompter, Unavailable};
    use std::time::Duration;

    const LONG: Duration = Duration::from_secs(60);

    fn route_to(backends: Vec<(&'static str, Arc<dyn Prompter>)>) -> Router {
        Router::new(backends)
    }

    async fn ask(router: &Router) -> io::Result<Answer> {
        router.ask("Allow?", &CancellationToken::new()).await
    }

    #[tokio::test]
    async fn first_answer_wins_and_withdraws_the_rest() {
        for answer in [true, false] {
            let slow = Arc::new(ApprovesAfter::new(LONG));
            let quick = Arc::new(ScriptedPrompter::with_confirms([answer]));
            let router = route_to(vec![("slow", slow.clone()), ("quick", quick.clone())]);

            let result = ask(&router).await.unwrap();
            assert_eq!(result.approved, answer);
            assert_eq!(result.by, "quick");
            assert_eq!(quick.asked(), ["Allow?"]);
            assert_eq!(slow.times_asked(), 1);
            assert_eq!(slow.times_cancelled(), 1);
        }
    }

    #[tokio::test]
    async fn giving_up_is_not_a_denial_while_another_backend_can_answer() {
        let gives_up = Arc::new(GivesUp::new(ErrorKind::TimedOut));
        let approves = Arc::new(ApprovesAfter::new(Duration::from_millis(20)));
        let router = route_to(vec![
            ("gives-up", gives_up.clone()),
            ("approves", approves.clone()),
        ]);

        let result = ask(&router).await.unwrap();
        assert!(result.approved);
        assert_eq!(result.by, "approves");
        // A timeout isn't a problem worth logging.
        assert!(result.problems.is_empty());
        assert_eq!(gives_up.times_asked(), 1);
        assert_eq!(approves.times_cancelled(), 0);
    }

    /// `sudo-agent approve` giving up because every client went isn't a
    /// failure either.
    #[tokio::test]
    async fn nobody_left_to_ask_is_not_a_problem() {
        let router = route_to(vec![
            ("approve", Arc::new(GivesUp::new(ErrorKind::NotConnected))),
            (
                "approves",
                Arc::new(ApprovesAfter::new(Duration::from_millis(20))),
            ),
        ]);
        let result = ask(&router).await.unwrap();
        assert!(result.approved);
        assert!(result.problems.is_empty(), "{:?}", result.problems);
    }

    #[tokio::test]
    async fn failures_are_reported_once() {
        let router = route_to(vec![
            ("broken", Arc::new(GivesUp::new(ErrorKind::Other))),
            (
                "approves",
                Arc::new(ApprovesAfter::new(Duration::from_millis(10))),
            ),
        ]);
        let first = ask(&router).await.unwrap();
        assert!(first.approved);
        assert_eq!(first.problems, [format!("broken: {}", GivesUp::REASON)]);
        let second = ask(&router).await.unwrap();
        assert!(second.approved);
        assert!(second.problems.is_empty());
    }

    #[tokio::test]
    async fn all_giving_up_denies_with_every_reason() {
        let router = route_to(vec![
            ("one", Arc::new(GivesUp::new(ErrorKind::TimedOut))),
            ("two", Arc::new(GivesUp::new(ErrorKind::Other))),
        ]);
        let e = ask(&router).await.unwrap_err();
        let message = e.to_string();
        assert!(message.contains("one: "), "{message}");
        assert!(message.contains("two: "), "{message}");
        assert_eq!(e.kind(), ErrorKind::Other);
    }

    #[tokio::test]
    async fn a_lone_backend_gives_its_own_reason() {
        let router = Router::only(Arc::new(GivesUp::new(ErrorKind::TimedOut)));
        let e = ask(&router).await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(e.to_string(), GivesUp::REASON);
    }

    #[tokio::test]
    async fn cancelling_the_request_withdraws_every_backend() {
        let one = Arc::new(ApprovesAfter::new(LONG));
        let two = Arc::new(ApprovesAfter::new(LONG));
        let router = Arc::new(route_to(vec![("one", one.clone()), ("two", two.clone())]));
        let cancel = CancellationToken::new();

        let asking = tokio::spawn({
            let (router, cancel) = (Arc::clone(&router), cancel.clone());
            async move { router.ask("Allow?", &cancel).await }
        });
        one.until_asked(1).await;
        two.until_asked(1).await;
        cancel.cancel();
        assert!(asking.await.unwrap().is_err());
        assert_eq!(one.times_cancelled(), 1);
        assert_eq!(two.times_cancelled(), 1);
    }

    #[tokio::test]
    async fn unavailable_backends_are_not_asked() {
        let quick = Arc::new(ScriptedPrompter::with_confirms([true]));
        let router = route_to(vec![
            ("unavailable", Arc::new(Unavailable)),
            ("quick", quick.clone()),
        ]);
        assert!(ask(&router).await.unwrap().approved);

        // `Unavailable` panics if asked.
        let router = route_to(vec![
            ("one", Arc::new(Unavailable)),
            ("two", Arc::new(Unavailable)),
        ]);
        let e = ask(&router).await.unwrap_err();
        assert_eq!(e.to_string(), "no approval backend is available");
    }
}
