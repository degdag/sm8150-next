// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/io_uring.h>

#include "refs.h"

int io_ring_ref_init(struct io_ring_ctx *ctx)
{
	size_t align = max_t(size_t, 1 << __PERCPU_REF_FLAG_BITS,
				__alignof__(unsigned long));

	ctx->ref_ptr = (unsigned long) __alloc_percpu(sizeof(unsigned long),
						      align);
	if (!ctx->ref_ptr)
		return -ENOMEM;

	return 0;
}

void io_ring_ref_free(struct io_ring_ctx *ctx)
{
	unsigned long __percpu *refs = io_ring_ref(ctx);

	free_percpu(refs);
	ctx->ref_ptr = 0;
}

void __cold io_ring_ref_maybe_done(struct io_ring_ctx *ctx)
{
	unsigned long __percpu *refs = io_ring_ref(ctx);
	unsigned long sum = 0;
	int cpu;

	preempt_disable();
	for_each_possible_cpu(cpu)
		sum += *per_cpu_ptr(refs, cpu);
	preempt_enable();

	if (!sum)
		complete(&ctx->ref_comp);
}

void io_ring_ref_kill(struct io_ring_ctx *ctx)
{
	set_bit(CTX_REF_DEAD_BIT, &ctx->ref_ptr);
	io_ring_ref_maybe_done(ctx);
}
