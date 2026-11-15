//! A global allocator for confined helpers: the system allocator, except that an allocation failure
//! is one `write(2)` of a fixed message on fd 2 (none if empty) and `exit_group(status)`. Rust's
//! default `handle_alloc_error` → `abort()` reaches `rt_sigprocmask` and dies by SIGSYS under a
//! minimal allowlist, indistinguishable from a policy violation.
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: ExitOnOom = ExitOnOom::new(b"my-helper: allocation failed\n", 71);
//! ```

use std::alloc::{GlobalAlloc, Layout, System};

pub struct ExitOnOom {
    message: &'static [u8],
    status: i32,
}

impl ExitOnOom {
    pub const fn new(message: &'static [u8], status: i32) -> Self {
        Self { message, status }
    }

    #[cold]
    #[inline(never)]
    fn failed(&self) -> ! {
        // SAFETY: write(2) of a static buffer and exit_group(2); no allocation, no unwinding.
        unsafe {
            if !self.message.is_empty() {
                libc::write(2, self.message.as_ptr().cast(), self.message.len());
            }
            libc::syscall(libc::SYS_exit_group, self.status);
        }
        unreachable!("exit_group returned")
    }
}

// SAFETY: forwards to `System`; never returns a null pointer to the caller.
unsafe impl GlobalAlloc for ExitOnOom {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(l) };
        if p.is_null() { self.failed() } else { p }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc_zeroed(l) };
        if p.is_null() { self.failed() } else { p }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let q = unsafe { System.realloc(p, l, n) };
        if q.is_null() { self.failed() } else { q }
    }
}
