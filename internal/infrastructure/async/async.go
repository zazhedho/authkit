// Package async runs fire-and-forget work (mail sends) with a concurrency cap,
// so a burst of requests cannot start unbounded goroutines.
package async

import (
	"context"
	"sync"
	"time"

	"github.com/zazhedho/logus"
)

// Runner runs background work, at most limit at a time. Work offered beyond
// that, or after Close, is dropped and logged.
type Runner struct {
	timeout time.Duration
	limit   int

	mu      sync.Mutex
	running int
	closed  bool
	waiters map[chan struct{}]struct{}
}

// New returns a Runner that runs at most limit jobs at once, each under timeout.
func New(limit int, timeout time.Duration) *Runner {
	return &Runner{limit: limit, timeout: timeout, waiters: map[chan struct{}]struct{}{}}
}

// Go runs fn in the background with ctx's values (request and user IDs for the
// logs) but not its cancellation, under the runner's timeout. It returns false
// and logs when the work was dropped.
func (r *Runner) Go(ctx context.Context, fn func(context.Context)) bool {
	r.mu.Lock()
	if r.closed || r.running >= r.limit {
		closed := r.closed
		r.mu.Unlock()
		logus.LogContextf(ctx, logus.LevelWarn, "async: background work dropped (closed=%v, limit=%d)", closed, r.limit)
		return false
	}
	r.running++
	r.mu.Unlock()

	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	go func() {
		defer r.finish()
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				logus.LogContextf(bg, logus.LevelError, "async: background work panicked: %v", p)
			}
		}()
		fn(bg)
	}()
	return true
}

func (r *Runner) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running--
	if r.running == 0 {
		for w := range r.waiters {
			close(w)
		}
		clear(r.waiters)
	}
}

// Wait blocks until the running jobs finish or ctx ends, and returns ctx's
// error in that case.
func (r *Runner) Wait(ctx context.Context) error {
	r.mu.Lock()
	if r.running == 0 {
		r.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	r.waiters[w] = struct{}{}
	r.mu.Unlock()
	select {
	case <-w:
		return nil
	case <-ctx.Done():
		r.mu.Lock()
		delete(r.waiters, w)
		r.mu.Unlock()
		return ctx.Err()
	}
}

// Close stops accepting work, then waits like Wait.
func (r *Runner) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.Wait(ctx)
}
