//! The single provider-owned database worker thread.
//!
//! All persistence runs here: one thread, one control connection plus lazily
//! opened account connections, and a bounded command queue. Commands are typed
//! at the API boundary — each carries its typed arguments and a typed reply
//! channel — so no caller can submit arbitrary SQL. The worker executes only
//! SQLite statements and in-memory work; it never awaits on network or
//! filesystem operations.

use crate::error::StateError;
use crate::store::Db;
use tokio::sync::{mpsc, oneshot};

const QUEUE_BOUND: usize = 256;

/// One queued command. `run` receives the worker's `Db` and answers its own
/// typed reply channel; `shutdown` additionally drains the queue and stops the
/// thread after the queued work is done.
pub(crate) struct Job {
    pub(crate) run: Box<dyn FnOnce(&mut Db) + Send + 'static>,
    pub(crate) shutdown: bool,
}

/// A clonable submission handle to the worker's bounded queue.
#[derive(Clone)]
pub(crate) struct Queue {
    tx: mpsc::Sender<Job>,
}

impl Queue {
    /// Enqueues one command and awaits its typed reply.
    pub(crate) async fn call<T, F>(&self, run: F) -> Result<T, StateError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Db) -> Result<T, StateError> + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job = Job {
            run: Box::new(move |db: &mut Db| {
                let _ = reply_tx.send(run(db));
            }),
            shutdown: false,
        };
        self.tx
            .send(job)
            .await
            .map_err(|_| StateError::WorkerStopped)?;
        reply_rx.await.map_err(|_| StateError::WorkerStopped)?
    }
}

pub(crate) struct Worker {
    queue: Option<Queue>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Worker {
    /// Spawns the worker and returns it together with the outcome of opening
    /// the databases.
    pub(crate) fn spawn(
        paths: crate::StatePaths,
    ) -> Result<(Self, oneshot::Receiver<Result<(), StateError>>), StateError> {
        let (tx, rx) = mpsc::channel(QUEUE_BOUND);
        let (init_tx, init_rx) = oneshot::channel();
        let handle = std::thread::Builder::new()
            .name("hfdrive-state-db".to_owned())
            .spawn(move || worker_main(paths, init_tx, rx))
            .map_err(StateError::Io)?;
        Ok((Self { queue: Some(Queue { tx }), handle: Some(handle) }, init_rx))
    }

    pub(crate) fn queue(&self) -> Queue {
        self.queue
            .as_ref()
            .expect("the queue lives as long as the worker")
            .clone()
    }

    /// Queues a shutdown after the commands already queued have run. The
    /// worker checkpoints the WAL before it exits.
    pub(crate) async fn shutdown(&self) -> Result<(), StateError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job = Job {
            run: Box::new(move |db: &mut Db| {
                let _ = reply_tx.send(db.checkpoint());
            }),
            shutdown: true,
        };
        self.queue()
            .tx
            .send(job)
            .await
            .map_err(|_| StateError::WorkerStopped)?;
        reply_rx.await.map_err(|_| StateError::WorkerStopped)??;
        Ok(())
    }

    /// Joins the worker thread. Blocks the calling task until the thread has
    /// exited, so callers run it on a blocking pool.
    pub(crate) async fn join(&mut self) -> Result<(), StateError> {
        // Drop our own sender first: the worker exits when its queue closes,
        // so holding the sender across a blocking join would deadlock.
        self.queue.take();
        if let Some(handle) = self.handle.take() {
            tokio::task::spawn_blocking(move || handle.join())
                .await
                .map_err(|_| StateError::WorkerStopped)?
                .map_err(|_| StateError::WorkerStopped)?;
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Queue a best-effort shutdown so the worker drains, checkpoints, and
        // exits even if `close` was never called; then release our sender.
        // The thread is deliberately not joined here: live `AccountStore`
        // handles may still hold queue senders, and blocking in `Drop` on
        // them would deadlock. Every command commits durably before replying,
        // so a detached exit loses nothing.
        if let Some(queue) = self.queue.as_ref() {
            let job = Job {
                run: Box::new(|db: &mut Db| {
                    let _ = db.checkpoint();
                }),
                shutdown: true,
            };
            let _ = queue.tx.try_send(job);
        }
        // With no account/queue handles left, no other sender can keep the
        // worker alive. Joining here prevents an immediate reopen from racing
        // the detached SQLite connection and seeing `DatabaseBusy`.
        let join = self.queue.as_ref().is_some_and(|queue| queue.tx.strong_count() == 1);
        self.queue.take();
        if join {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

fn worker_main(
    paths: crate::StatePaths,
    init_tx: oneshot::Sender<Result<(), StateError>>,
    mut rx: mpsc::Receiver<Job>,
) {
    let mut db = match Db::open(paths) {
        Ok(db) => db,
        Err(error) => {
            let _ = init_tx.send(Err(error));
            return;
        }
    };
    if init_tx.send(Ok(())).is_err() {
        // The caller went away before the databases were opened.
        return;
    }
    while let Some(job) = rx.blocking_recv() {
        let shutdown = job.shutdown;
        (job.run)(&mut db);
        if shutdown {
            // Drain the commands that were already queued before stopping; a
            // command queued after this point fails with `WorkerStopped`.
            while let Ok(job) = rx.try_recv() {
                (job.run)(&mut db);
            }
            break;
        }
    }
    let _ = db.checkpoint();
}
