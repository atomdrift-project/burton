//! A global allocator that counts, per thread, what a closure allocates.
//!
//! Counts are exact and independent of machine load, which is what lets
//! budgets on them be hard assertions. Counting is per thread, so tests
//! measuring in parallel do not see each other.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// [`System`], plus bookkeeping while [`measure`] runs on this thread.
pub(crate) struct Counting;

/// What one [`measure`] call allocated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    /// Allocations, counting each reallocation as one.
    pub(crate) allocs: u64,
    /// Bytes requested across all of them.
    pub(crate) bytes: u64,
    /// Most bytes live at once, above what was live on entry.
    pub(crate) peak: u64,
    live: i64,
}

thread_local! {
    static USAGE: Cell<Option<Usage>> = const { Cell::new(None) };
}

fn record(grow: usize, shrink: usize, is_alloc: bool) {
    // `try_with`: the allocator also runs while thread-locals are torn down.
    let _ = USAGE.try_with(|cell| {
        if let Some(mut u) = cell.get() {
            if is_alloc {
                u.allocs += 1;
                u.bytes += grow as u64;
            }
            let signed = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
            u.live += signed(grow) - signed(shrink);
            u.peak = u.peak.max(u.live.max(0).unsigned_abs());
            cell.set(Some(u));
        }
    });
}

// SAFETY: every method forwards to `System` unchanged; the bookkeeping only
// touches a const-initialized thread-local `Cell`, which never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size(), 0, true);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size(), 0, true);
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(0, layout.size(), false);
        // SAFETY: `ptr` came from `System` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size, layout.size(), true);
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Run `f`, returning its result and what it allocated on this thread.
pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Usage) {
    USAGE.set(Some(Usage::default()));
    let out = f();
    let usage = USAGE.take().unwrap_or_default();
    (out, usage)
}
