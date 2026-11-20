// Package async runs fire-and-forget work (mail sends) with a concurrency cap,
// so a burst of requests cannot start unbounded goroutines.
package async

import (
	"context"
	"sync"
	"time"

	"github.com/zazhedho/logus"
)

// Runner runs background work, at most limit at a time. Work offered beyond that
// is dropped and logged.
type Runner struct {
	sem     chan struct{}
	timeout time.Duration
	wg      sync.WaitGroup
}

// New returns a Runner that runs at most limit jobs at once, each under timeout.
func New(limit int, timeout time.Duration) *Runner {
	return &Runner{sem: make(chan struct{}, limit), timeout: timeout}
}

// Go runs fn in the background with ctx's values (request and user IDs for the
// logs) but not its cancellation, under the runner's timeout. It returns false
// and logs when the runner is full.
func (r *Runner) Go(ctx context.Context, fn func(context.Context)) bool {
	select {
	case r.sem <- struct{}{}:
	default:
		logus.LogContextf(ctx, logus.LevelWarn, "async: at capacity (%d), background work dropped", cap(r.sem))
		return false
	}
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.sem }()
		defer cancel()
		fn(bg)
	}()
	return true
}

// Wait blocks until the running jobs finish or ctx ends, and returns ctx's
// error in that case.
func (r *Runner) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
