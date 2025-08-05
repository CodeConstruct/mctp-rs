// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2025 Code Construct
 */

//! A specialised executor for testing.
//!
//! The `StepExecutor` allows run-until-idle, and also
//! also ensures that each task runs with a distinct waker.
//!
//! Currently this doesn't have a mechanism to run beneath other executors,
//! which would be required to interface with external IO triggers.
//! That could be added in future by proxying `wake()` calls to a parent executor.

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use core::future::poll_fn;
use futures::FutureExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};

/// A test executor
///
/// This allows control of task execution.
/// The executor is not designed to be efficient.
#[derive(Debug)]
pub struct StepExecutor<'a> {
    /// Futures that run at any time
    tasks: Vec<(Task<'a>, Arc<Pender>)>,

    /// Futures that only run when requested
    sub_tasks: SubTaskRunner,

    /// A counter, incremented by any wake in any task or subtask.
    ///
    /// Used for pessimistic modification detection. Won't overflow.
    counter: Arc<AtomicU64>,
}

impl<'a> StepExecutor<'a> {
    pub fn new() -> Self {
        let counter = Arc::new(AtomicU64::new(1));
        Self {
            tasks: Vec::new(),
            sub_tasks: SubTaskRunner {
                penders: Default::default(),
                counter: counter.clone(),
            },
            counter,
        }
    }

    /// Retrieves a `SubTaskRunner`.
    ///
    /// That can be used to start subtasks, and wait for idleness.
    pub fn sub_runner(&self) -> SubTaskRunner {
        self.sub_tasks.clone()
    }

    /// Adds a future that will run at any time.
    ///
    /// The future will run to completion, with output discarded.
    pub fn add<F: Future<Output = R> + 'a + Sync + Send, R>(&mut self, f: F) {
        let task = Task::new(f);
        let pender = Arc::new(Pender::new(self.counter.clone()));
        trace!(
            "Add task {}. New pender {}",
            self.tasks.len(),
            pender.debug_id()
        );
        self.tasks.push((task, pender));
    }

    /// Adds a future and runs the executor until the future completes.
    ///
    /// Returns an error if the executor went idle before the future completes.
    ///
    /// TODO: eventually it might be nice to take an `AsyncFnOnce(SubTaskRunner)`
    /// argument instead, but at present (Rust 1.89) they can't be expressed as
    /// `Sync+Send`.
    pub fn run_to_completion<F, R>(&mut self, f: F) -> Result<(), IterLimit>
    where
        F: Future<Output = R> + 'a + Sync + Send,
    {
        self.add(f);
        let (_t, pender) = self.tasks.last().unwrap();

        // Keep running until the task is removed.
        let pender = Arc::downgrade(pender);
        self.until_idle();
        if pender.strong_count() > 0 {
            trace!("Future didn't complete");
            Err(IterLimit)
        } else {
            Ok(())
        }
    }

    fn all_main_idle(&self) -> bool {
        self.tasks.iter().all(|(_t, p)| !p.is_pending())
    }

    /// Run the executor until no more forward progress can be made.
    ///
    /// It is possible for this to never complete if task(s) are continually
    /// waking.
    pub fn until_idle(&mut self) {
        // A single CPU can't count to u64::MAX
        self.until_idle_limit_iter(u64::MAX).unwrap()
    }

    /// Run the executor until all tasks complete
    pub fn run_all(mut self) {
        while !self.tasks.is_empty() {
            self.until_idle();
        }
    }

    /// The same as until_idle but with an iteration limit
    ///
    /// Can be used when testing for expected infinite loops.
    /// Note that scheduler order is undefined, so even finite loops
    /// could possibly run for a very long time.
    ///
    /// Returns Ok((()) if idle, Err(IterLimit) on iteration limit hit.
    pub fn until_idle_limit_iter(
        &mut self,
        iters: u64,
    ) -> Result<(), IterLimit> {
        '_outer: for _ in 0..iters {
            trace!("loop top");
            // Check whether all tasks have completed, prior to looking for
            // idle waiters.
            let main_idle = self.all_main_idle();

            let mut sub_idle = true;
            // Iterate over all the live subtasks to find ones where
            // another task is waiting for idleness.
            for p in self
                .sub_tasks
                .penders
                .lock()
                .unwrap()
                .iter()
                .filter_map(|p| p.upgrade())
            {
                p.with(|p| {
                    while let Some(p) = p.subtask_idle_waiters.pop() {
                        sub_idle = false;
                        p.wake();
                    }
                    p.subtask_idle = main_idle;
                    // Read the counter after waking idle waiters. Otherwise
                    // subtask_idle_counter will always be outdated (wake() increments
                    // the global counter).
                    //
                    // There is still the chance that a future wake
                    // makes the counter outdated before being compared,
                    // but in that case another 'outer loop will occur and will eventually
                    // run with a not-outdated counter.
                    let now = self.counter.load(Ordering::SeqCst);
                    p.subtask_idle_counter = now;
                })
            }

            trace!("main_idle {main_idle:?} sub_idle {sub_idle:?}");

            if main_idle && sub_idle {
                // Reached quiescent state.
                return Ok(());
            }

            // Run tasks, removing completed ones.
            self.tasks.retain_mut(|(t, pender)| {
                // Clear pending flag
                if pender.clear() {
                    // Poll pending tasks
                    let w = Waker::from(pender.clone());
                    let mut cx = Context::from_waker(&w);
                    if t.fut.poll_unpin(&mut cx).is_ready() {
                        // Task is done, remove it.
                        return false;
                    }
                }
                true
            });
        }
        Err(IterLimit)
    }
}

impl Default for StepExecutor<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when an iteration limit is reached.
#[derive(Debug)]
pub struct IterLimit;

/// Represents the wakeup state of a task.
///
/// An `Arc<Pender>` is passed as a "task handle", and is convertible to/from a `Waker`
/// via `StepExecutor::task_from_waker()`. `PenderHandle` implements hash etc as a newtype.
#[derive(Debug)]
struct Pender {
    inner: Mutex<PenderInner>,
    counter: Arc<AtomicU64>,
}

impl Pender {
    fn new(counter: Arc<AtomicU64>) -> Self {
        trace!("Pender new, counter {}", counter.load(Ordering::SeqCst));
        assert_ne!(counter.load(Ordering::SeqCst), 0);
        let inner = PenderInner {
            // New tasks are pending to poll at least once.
            pending: true,
            subtask_idle_waiters: Vec::new(),
            subtask_idle: false,
            subtask_idle_counter: 0,
        };
        Self {
            inner: Mutex::new(inner),
            counter,
        }
    }

    fn debug_id(self: &Arc<Self>) -> String {
        format!("Pender({:#x?})", Arc::as_ptr(self))
    }

    fn with<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut PenderInner) -> R,
    {
        let mut p = self.inner.lock().unwrap();
        f(&mut p)
    }

    /// Clears the pending bit, returns the previous value.
    fn clear(&self) -> bool {
        self.with(|p| core::mem::replace(&mut p.pending, false))
    }

    fn is_pending(&self) -> bool {
        self.with(|p| p.pending)
    }

    fn read_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Wake for Pender {
    fn wake(self: Arc<Self>) {
        trace!("wake {}", self.debug_id());
        self.counter.fetch_add(1, Ordering::SeqCst);
        self.with(|p| {
            p.pending = true;
            // Wake any parent waiters of a subtask
            for wt in &p.subtask_idle_waiters {
                wt.wake_by_ref();
            }
        })
    }
}

#[derive(Debug)]
struct PenderInner {
    /// Only set by wake()
    pending: bool,

    /// For subtasks, a list of other tasks waiting for this to go idle.
    subtask_idle_waiters: Vec<Waker>,

    /// Set true when idle.
    ///
    /// Is set pessemistically. Should be discarded if counter has advanced
    /// past subtask_idle_counter.
    subtask_idle: bool,

    /// Counter value when subtask_idle was set, to track staleness.
    subtask_idle_counter: u64,
}

/// State shared between `StepExecutor` and tasks.
#[derive(Clone, Debug)]
pub struct SubTaskRunner {
    penders: Arc<Mutex<Vec<Weak<Pender>>>>,
    counter: Arc<AtomicU64>,
}

impl SubTaskRunner {
    /// Starts a subtask.
    pub fn start<'a, F: Future<Output = R> + 'a + Sync + Send, R>(
        &self,
        f: F,
    ) -> SubTask<'a, R> {
        trace!("Start, counter {}", self.counter.load(Ordering::SeqCst));
        let st = SubTask::new(f, self.counter.clone());
        self.penders
            .lock()
            .unwrap()
            .push(Arc::downgrade(&st.pender));
        st
    }

    /// Starts a subtask and runs it until all tasks are idle.
    ///
    /// Returns `Ok` if it goes idle, or `Err` with the result if it completes early.
    pub async fn start_until_idle<
        'a,
        F: Future<Output = R> + 'a + Sync + Send,
        R,
    >(
        &self,
        f: F,
    ) -> Result<SubTask<'a, R>, R> {
        let mut st = self.start(f);
        match st.run_until_idle().await {
            Some(r) => Err(r),
            None => Ok(st),
        }
    }

    /// Waits for all tasks to be idle.
    pub async fn wait_idle(&self) {
        self.start_until_idle(smol::future::pending::<()>())
            .await
            .unwrap();
    }
}

pub struct SubTask<'a, R> {
    // See Sync+Send comment on `struct Task`
    fut: Pin<Box<dyn Future<Output = R> + 'a + Sync + Send>>,
    // Has a corresponding pender in StepExecutor's sub_tasks
    pender: Arc<Pender>,

    // Task is complete.
    done: bool,
}

impl<R> core::fmt::Debug for SubTask<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubTask")
            .field("pender", &self.pender)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<'a, R> SubTask<'a, R> {
    /// Constructed via SubTaskList::start()
    fn new<F: Future<Output = R> + 'a + Sync + Send>(
        fut: F,
        counter: Arc<AtomicU64>,
    ) -> Self {
        let fut = Box::pin(fut);
        Self {
            fut,
            pender: Arc::new(Pender::new(counter)),
            done: false,
        }
    }

    /// Called by another task to progress this task, until all tasks go idle.
    ///
    /// Returns Some if the subtask completes, None otherwise.
    ///
    /// Panics if called after `SubTask` completion.
    /// `StepExecutor` will later panic if `SubTask::run_until_idle`
    /// is called from a different executor.
    ///
    /// Note: This may only be called by main tasks (ones started with
    /// `StepExecutor::add()`). Subtasks will currently panic if they call
    /// run_until_idle(). In future that could be added.
    pub async fn run_until_idle(&mut self) -> Option<R> {
        if self.done {
            panic!("Can't run_until_idle() after completion");
        }

        poll_fn(|cx| {
            self.pender.clear();
            trace!("run_until_idle prepoll");
            if let Poll::Ready(r) = self.fut.poll_unpin(cx) {
                // The subtask completed
                trace!("run_until_idle ready {:?}", cx.waker());
                self.done = true;
                return Poll::Ready(Some(r));
            }

            let (idle, idle_counter) = self
                .pender
                .with(|p| (p.subtask_idle, p.subtask_idle_counter));
            let now = self.pender.read_counter();
            if idle && idle_counter == now {
                // All tasks were idle.
                trace!("run_until_idle idle {:?}", cx.waker());
                return Poll::Ready(None);
            }
            trace!("idle {idle:?} idle_counter {idle_counter} now {now}");

            // StepExecutor will periodically uniquify the list TODO check.
            trace!("run_until_idle push {:?}", cx.waker());
            self.pender
                .with(|p| p.subtask_idle_waiters.push(cx.waker().clone()));
            Poll::Pending
        })
        .await
    }
}

/// Poll the task's future to completion.
impl<R> Future for SubTask<'_, R> {
    type Output = R;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        if self.done {
            panic!("Can't await after completion");
        }

        self.pender.clear();
        let r = self.fut.poll_unpin(cx);
        self.done = r.is_ready();
        r
    }
}

/// Holds a pinned boxed future.
///
/// The future's output is discarded on completion.
///
/// TODO: Currently this has `Sync + Send` bounds (easier to relax later),
/// but they're expected to run in a single threaded `StepExecutor` instance.
/// Is there a use case for `Sync + Send` (sending to other executors?), or should
/// the bounds be removed?
struct Task<'a> {
    fut: Pin<Box<dyn Future<Output = ()> + 'a + Sync + Send>>,
}

impl core::fmt::Debug for Task<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Task").finish_non_exhaustive()
    }
}

impl<'a> Task<'a> {
    fn new<F: Future<Output = R> + 'a + Sync + Send, R>(fut: F) -> Self {
        // Convert the future to return ()
        let fut = async {
            fut.await;
        };

        let fut = Box::pin(fut);
        Self { fut }
    }
}

fn start_log() {
    let _ = env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .is_test(true)
        .try_init();
}

#[test]
fn step_executor_1() {
    start_log();

    let mut ex = StepExecutor::default();
    let (ex1_s, ex1_r) = smol::channel::bounded(1);
    let (ex2_s, ex2_r) = smol::channel::bounded(1);
    let (ex3_s, ex3_r) = smol::channel::bounded(1);
    let (sub_s, sub_r) = smol::channel::bounded(1);

    trace!("top");
    ex.add(async move {
        for i in 0..5 {
            trace!("ex1 {i}");
            smol::future::yield_now().await;
        }
        ex1_s.try_send(()).unwrap();

        smol::future::pending::<()>().await;
        unreachable!();
    });

    ex.add(async move {
        for i in 0..10 {
            trace!("ex2 {i}");
            smol::future::yield_now().await;
        }
        ex2_s.try_send(()).unwrap();
    });

    let sub = ex.sub_runner();

    ex.add(async move {
        let f = async {
            for i in 0..10 {
                trace!("f {i}");
                smol::future::yield_now().await;
                smol::future::yield_now().await;
                smol::future::yield_now().await;
            }
            sub_s.try_send(5).unwrap();
            smol::future::pending::<u8>().await;
        };

        let mut f = sub.start(f);
        match f.run_until_idle().await {
            Some(r) => {
                info!("sub wait result {r:?}");
                panic!("No result should be returned");
            }
            None => info!("sub wait idle"),
        }
        ex3_s.try_send(()).unwrap();

        // let t = ex.
    });

    assert!(ex1_r.try_recv().is_err());
    assert!(ex2_r.try_recv().is_err());
    assert!(ex3_r.try_recv().is_err());

    ex.until_idle();

    assert!(ex1_r.try_recv().is_ok());
    assert!(ex2_r.try_recv().is_ok());
    assert!(ex3_r.try_recv().is_ok());
    assert!(sub_r.try_recv().is_ok());
}

#[test]
fn step_executor_subtask_yield() {
    start_log();

    let mut ex = StepExecutor::default();
    let (ex3_s, ex3_r) = smol::channel::bounded(1);

    let sub = ex.sub_runner();

    ex.add(async move {
        let f = async {
            for i in 0..10 {
                trace!("f {i}");
                smol::future::yield_now().await;
                smol::future::yield_now().await;
                smol::future::yield_now().await;
            }
            "the end."
        };

        let mut f = sub.start(f);
        let r = f.run_until_idle().await;
        assert_eq!(r, Some("the end."));
        ex3_s.try_send(()).unwrap();
    });

    assert!(ex3_r.try_recv().is_err());

    ex.until_idle();

    assert!(ex3_r.try_recv().is_ok());
}

#[test]
fn step_executor_subtask_pending() {
    start_log();

    let mut ex = StepExecutor::default();
    let (ex3_s, ex3_r) = smol::channel::bounded(1);

    let sub = ex.sub_runner();

    ex.add(async move {
        let f = async {
            smol::future::yield_now().await;
            smol::future::pending::<u32>().await
        };

        let mut f = sub.start(f);
        let r = f.run_until_idle().await;
        assert!(r.is_none());
        ex3_s.try_send("done").unwrap();
    });

    assert!(ex3_r.try_recv().is_err());

    ex.until_idle();

    assert_eq!(ex3_r.try_recv(), Ok("done"))
}

#[test]
fn step_executor_subtask_busy() {
    start_log();

    let mut ex = StepExecutor::default();

    let sub = ex.sub_runner();

    // Add an unrelated main task that is never idle
    ex.add(async move {
        for _ in 0..10 {
            smol::future::yield_now().await;
        }
    });

    ex.add(async move {
        let f = async {
            loop {
                smol::future::yield_now().await;
            }
        };

        let mut f = sub.start(f);
        f.run_until_idle().await;
        unreachable!()
    });

    let run = ex.until_idle_limit_iter(1000);
    assert!(run.is_err(), "the subtask shouldn't return return");
}

#[test]
fn step_executor_subtask_other_busy() {
    start_log();

    let mut ex = StepExecutor::default();

    let sub = ex.sub_runner();

    // Add an unrelated main task that is never idle
    ex.add(async move {
        loop {
            smol::future::yield_now().await;
        }
    });

    ex.add(async move {
        let f = async {
            for _ in 0..5 {
                smol::future::yield_now().await;
            }
            "done"
        };

        let mut f = sub.start(f);
        assert_eq!(f.run_until_idle().await, Some("done"));
    });

    let run = ex.until_idle_limit_iter(1000);
    assert!(run.is_err(), "the first loop shouldn't return");
}
