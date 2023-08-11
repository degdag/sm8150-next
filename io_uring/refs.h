#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define req_ref_zero_or_close_to_overflow(req)	\
	((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	return atomic_inc_not_zero(&req->refs);
}

static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))
		return true;

	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_inc(&req->refs);
}

static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {
		req->flags |= REQ_F_REFCOUNT;
		atomic_set(&req->refs, nr);
	}
}

static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);
}

int io_ring_ref_init(struct io_ring_ctx *ctx);
void io_ring_ref_free(struct io_ring_ctx *ctx);
void __cold io_ring_ref_maybe_done(struct io_ring_ctx *ctx);
void io_ring_ref_kill(struct io_ring_ctx *ctx);

enum {
	CTX_REF_DEAD_BIT	= 0UL,
	CTX_REF_DEAD_MASK	= 1UL,
};

static inline unsigned long __percpu *io_ring_ref(struct io_ring_ctx *ctx)
{
	return (unsigned long __percpu *) (ctx->ref_ptr & ~CTX_REF_DEAD_MASK);
}

static inline bool io_ring_ref_is_dying(struct io_ring_ctx *ctx)
{
	return test_bit(CTX_REF_DEAD_BIT, &ctx->ref_ptr);
}

static inline void io_ring_ref_get_many(struct io_ring_ctx *ctx, unsigned long nr)
{
	unsigned long __percpu *refs = io_ring_ref(ctx);

	preempt_disable();
	this_cpu_add(*refs, nr);
	preempt_enable();
}

static inline void io_ring_ref_get(struct io_ring_ctx *ctx)
{
	io_ring_ref_get_many(ctx, 1);
}

static inline void io_ring_ref_put_many(struct io_ring_ctx *ctx, unsigned long nr)
{
	unsigned long __percpu *refs = io_ring_ref(ctx);

	preempt_disable();
	this_cpu_sub(*refs, nr);
	preempt_enable();

	if (unlikely(io_ring_ref_is_dying(ctx)))
		io_ring_ref_maybe_done(ctx);
}

static inline void io_ring_ref_put(struct io_ring_ctx *ctx)
{
	io_ring_ref_put_many(ctx, 1);
}

#endif
