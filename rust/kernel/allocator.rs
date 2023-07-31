// SPDX-License-Identifier: GPL-2.0

//! Allocator support.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::bindings;

struct KernelAllocator;

impl KernelAllocator {
    /// # Safety
    ///
    /// - `ptr` can be either null or a pointer which has been allocated by this allocator.
    /// - `layout` must have a non-zero size.
    unsafe fn krealloc_with_flags(
        &self,
        ptr: *mut u8,
        layout: Layout,
        flags: bindings::gfp_t,
    ) -> *mut u8 {
        // Customized layouts from `Layout::from_size_align()` can have size < align, so pad first.
        let layout = layout.pad_to_align();

        let mut size = layout.size();

        if layout.align() > bindings::BINDINGS_ARCH_SLAB_MINALIGN {
            // The alignment requirement exceeds the slab guarantee, thus try to enlarge the size
            // to use the "power-of-two" size/alignment guarantee (see comments in `kmalloc()` for
            // more information).
            //
            // Note that `layout.size()` (after padding) is guaranteed to be a multiple of
            // `layout.align()`, so `next_power_of_two` gives enough alignment guarantee.
            size = size.next_power_of_two();
        }

        // SAFETY:
        // - `ptr` is either null or a pointer returned from a previous `k{re}alloc()` by the
        //   function safety requirement.
        // - `size` is greater than 0 since it's either a `layout.size()` (which cannot be zero
        //    according to the function safety requirement) or a result from `next_power_of_two()`.
        unsafe { bindings::krealloc(ptr as *const core::ffi::c_void, size, flags) as *mut u8 }
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `ptr::null_mut()` is null and `layout` has a non-zero size by the function safety
        // requirement.
        unsafe { self.krealloc_with_flags(ptr::null_mut(), layout, bindings::GFP_KERNEL) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            bindings::kfree(ptr as *const core::ffi::c_void);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY:
        // - `new_size`, when rounded up to the nearest multiple of `layout.align()`, will not
        //   overflow `isize` by the function safety requirement.
        // - `layout.align()` is a proper alignment (i.e. not zero and must be a power of two).
        let layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };

        // SAFETY:
        // - `ptr` is either null or a pointer allocated by this allocator by the function safety
        //   requirement.
        // - the size of `layout` is not zero because `new_size` is not zero by the function safety
        //   requirement.
        unsafe { self.krealloc_with_flags(ptr, layout, bindings::GFP_KERNEL) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `ptr::null_mut()` is null and `layout` has a non-zero size by the function safety
        // requirement.
        unsafe {
            self.krealloc_with_flags(
                ptr::null_mut(),
                layout,
                bindings::GFP_KERNEL | bindings::__GFP_ZERO,
            )
        }
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

// `rustc` only generates these for some crate types. Even then, we would need
// to extract the object file that has them from the archive. For the moment,
// let's generate them ourselves instead.
//
// Note that `#[no_mangle]` implies exported too, nowadays.
#[no_mangle]
fn __rust_alloc(size: usize, _align: usize) -> *mut u8 {
    unsafe { bindings::krealloc(core::ptr::null(), size, bindings::GFP_KERNEL) as *mut u8 }
}

#[no_mangle]
fn __rust_dealloc(ptr: *mut u8, _size: usize, _align: usize) {
    unsafe { bindings::kfree(ptr as *const core::ffi::c_void) };
}

#[no_mangle]
fn __rust_realloc(ptr: *mut u8, _old_size: usize, _align: usize, new_size: usize) -> *mut u8 {
    unsafe {
        bindings::krealloc(
            ptr as *const core::ffi::c_void,
            new_size,
            bindings::GFP_KERNEL,
        ) as *mut u8
    }
}

#[no_mangle]
fn __rust_alloc_zeroed(size: usize, _align: usize) -> *mut u8 {
    unsafe {
        bindings::krealloc(
            core::ptr::null(),
            size,
            bindings::GFP_KERNEL | bindings::__GFP_ZERO,
        ) as *mut u8
    }
}
