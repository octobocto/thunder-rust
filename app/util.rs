//! Convenience and utility types and functions

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::{marker::Unpin, task::Poll};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use futures::{Stream, StreamExt};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use poll_promise::Promise;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
type PromiseStreamInner<S> = Promise<Option<(S, <S as Stream>::Item)>>;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub struct PromiseStream<S>(Option<PromiseStreamInner<S>>)
where
    S: Send + Stream + 'static,
    S::Item: Send;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl<S> PromiseStream<S>
where
    S: Send + Stream + Unpin + 'static,
    S::Item: Send,
{
    fn promise(mut stream: S) -> Promise<Option<(S, S::Item)>>
    where
        S:,
    {
        Promise::spawn_async(async {
            stream.next().await.map(|item| (stream, item))
        })
    }

    /// Get the next item in the stream if available,
    /// or return None if the stream is complete
    pub fn poll_next(&mut self) -> Option<Poll<S::Item>> {
        let res;
        let inner = std::mem::take(&mut self.0);
        self.0 = match inner {
            Some(promise) => match promise.try_take() {
                Ok(Some((stream, item))) => {
                    res = Some(Poll::Ready(item));
                    Some(Self::promise(stream))
                }
                Ok(None) => {
                    res = None;
                    None
                }
                Err(promise) => {
                    res = Some(Poll::Pending);
                    Some(promise)
                }
            },
            None => {
                res = None;
                None
            }
        };
        res
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl<S> From<S> for PromiseStream<S>
where
    S: Send + Stream + Unpin + 'static,
    S::Item: Send,
{
    fn from(stream: S) -> Self {
        Self(Some(Self::promise(stream)))
    }
}
