//! Approval routing: every available backend (the terminal; later pinentry
//! and `sudo-agent approve` clients) is asked at once, and the first answer
//! wins.

use std::future::{Future, poll_fn};
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::prompt::Prompter;

/// An approval backend and the name its reasons are logged under.
struct Backend {
    name: &'static str,
    prompter: Arc<dyn Prompter>,
}

/// A [`Prompter`] for approvals that asks every available backend at once.
/// The first answer (approve or deny) wins, and the other backends are
/// withdrawn. A backend that gives up (times out, fails) is no answer, not a
/// denial: the request is only denied once all of them have given up, or if
/// none is available.
pub struct Router {
    backends: Vec<Backend>,
}

impl Router {
    pub fn new(backends: impl IntoIterator<Item = (&'static str, Arc<dyn Prompter>)>) -> Self {
        let backends = backends
            .into_iter()
            .map(|(name, prompter)| Backend { name, prompter })
            .collect();
        Self { backends }
    }
}

/// One backend's open question.
type Asking<'a> = Pin<Box<dyn Future<Output = io::Result<bool>> + Send + 'a>>;

#[async_trait]
impl Prompter for Router {
    /// Passphrases aren't routed: the terminal asks for them directly, once,
    /// at startup.
    async fn passphrase(&self, _: &str) -> io::Result<Zeroizing<String>> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "passphrases aren't routed",
        ))
    }

    async fn confirm(&self, message: &str, cancel: &CancellationToken) -> io::Result<bool> {
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
                    return Ok(approved);
                }
                Err(e) => gave_up.push((name, e)),
            }
        }
        Err(no_answer(gave_up))
    }
}

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

    fn route_to(backends: Vec<Arc<dyn Prompter>>) -> Router {
        Router::new(backends.into_iter().map(|backend| ("test", backend)))
    }

    #[tokio::test]
    async fn first_answer_wins_and_withdraws_the_rest() {
        for answer in [true, false] {
            let slow = Arc::new(ApprovesAfter::new(LONG));
            let quick = Arc::new(ScriptedPrompter::with_confirms([answer]));
            let router = route_to(vec![slow.clone(), quick.clone()]);

            let result = router.confirm("Allow?", &CancellationToken::new()).await;
            assert_eq!(result.unwrap(), answer);
            assert_eq!(quick.asked(), ["Allow?"]);
            assert_eq!(slow.times_asked(), 1);
            assert_eq!(slow.times_cancelled(), 1);
        }
    }

    #[tokio::test]
    async fn giving_up_is_not_a_denial_while_another_backend_can_answer() {
        let gives_up = Arc::new(GivesUp::new(ErrorKind::TimedOut));
        let approves = Arc::new(ApprovesAfter::new(Duration::from_millis(20)));
        let router = route_to(vec![gives_up.clone(), approves.clone()]);

        let result = router.confirm("Allow?", &CancellationToken::new()).await;
        assert!(result.unwrap());
        assert_eq!(gives_up.times_asked(), 1);
        assert_eq!(approves.times_cancelled(), 0);
    }

    #[tokio::test]
    async fn all_giving_up_denies_with_every_reason() {
        let router = Router::new([
            (
                "one",
                Arc::new(GivesUp::new(ErrorKind::TimedOut)) as Arc<dyn Prompter>,
            ),
            ("two", Arc::new(GivesUp::new(ErrorKind::Other))),
        ]);
        let e = router
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        let message = e.to_string();
        assert!(message.contains("one: "), "{message}");
        assert!(message.contains("two: "), "{message}");
        assert_eq!(e.kind(), ErrorKind::Other);
    }

    #[tokio::test]
    async fn a_lone_backend_gives_its_own_reason() {
        let router = route_to(vec![Arc::new(GivesUp::new(ErrorKind::TimedOut))]);
        let e = router
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(e.to_string(), GivesUp::REASON);
    }

    #[tokio::test]
    async fn cancelling_the_request_withdraws_every_backend() {
        let one = Arc::new(ApprovesAfter::new(LONG));
        let two = Arc::new(ApprovesAfter::new(LONG));
        let router = Arc::new(route_to(vec![one.clone(), two.clone()]));
        let cancel = CancellationToken::new();

        let asking = tokio::spawn({
            let (router, cancel) = (Arc::clone(&router), cancel.clone());
            async move { router.confirm("Allow?", &cancel).await }
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
        let router = route_to(vec![Arc::new(Unavailable), quick.clone()]);
        let result = router.confirm("Allow?", &CancellationToken::new()).await;
        assert!(result.unwrap());

        // `Unavailable` panics if asked.
        let router = route_to(vec![Arc::new(Unavailable), Arc::new(Unavailable)]);
        let e = router
            .confirm("Allow?", &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "no approval backend is available");
    }

    #[tokio::test]
    async fn passphrases_are_not_routed() {
        let router = route_to(vec![Arc::new(ScriptedPrompter::with_passphrases(["x"]))]);
        let e = router.passphrase("Passphrase").await.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported);
    }
}
