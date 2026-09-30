use super::{FipsPubsubClient, JoinHandle};

pub(super) struct ClientTasks {
    pub(super) transport: Option<JoinHandle<()>>,
    pub(super) peerfinding: Option<JoinHandle<()>>,
    pub(super) reputation: Option<JoinHandle<()>>,
}

impl ClientTasks {
    fn slots(&mut self) -> impl Iterator<Item = &mut Option<JoinHandle<()>>> {
        [
            &mut self.reputation,
            &mut self.peerfinding,
            &mut self.transport,
        ]
        .into_iter()
    }

    fn abort_all(&mut self) {
        for task in self.slots().flatten() {
            task.abort();
        }
    }
}

impl FipsPubsubClient {
    /// Stop the client and join every owned background task.
    pub async fn shutdown(self) {
        self.shutdown_shared().await;
    }

    /// Stop a client even while application providers retain an `Arc` to it.
    ///
    /// Closes subscriptions and rejects new queries, subscriptions, and
    /// publications. Concurrent callers wait for the same task completion;
    /// cancellation of one caller leaves unfinished joins for the next caller.
    /// The application-owned FIPS endpoint stays running.
    pub async fn shutdown_shared(&self) {
        self.inner.close_all();
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        for slot in tasks.slots() {
            if let Some(task) = slot.as_mut() {
                let _ = task.await;
            }
            slot.take();
        }
    }
}

impl Drop for FipsPubsubClient {
    fn drop(&mut self) {
        self.inner.close_all();
        self.tasks.get_mut().abort_all();
    }
}
