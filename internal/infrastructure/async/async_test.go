package async

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type ctxKey struct{}

func TestGoRunsWithTheCallersValuesButNotItsCancellation(t *testing.T) {
	r := New(2, time.Second)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), ctxKey{}, "req-1"))
	got := make(chan string, 1)
	canceled := make(chan bool, 1)
	if !r.Go(ctx, func(bg context.Context) {
		<-ctx.Done() // the request is over before the work runs
		got <- bg.Value(ctxKey{}).(string)
		canceled <- bg.Err() != nil
	}) {
		t.Fatal("work was dropped")
	}
	cancel()
	if v := <-got; v != "req-1" {
		t.Fatalf("value = %q", v)
	}
	if <-canceled {
		t.Fatal("the background context must outlive the request")
	}
	if err := r.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestGoGivesTheWorkATimeout(t *testing.T) {
	r := New(1, 20*time.Millisecond)
	done := make(chan error, 1)
	r.Go(t.Context(), func(bg context.Context) {
		<-bg.Done()
		done <- bg.Err()
	})
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestGoDropsWorkWhenTheLimitIsReached(t *testing.T) {
	r := New(2, time.Minute)
	release := make(chan struct{})
	var ran atomic.Int32
	for range 2 {
		if !r.Go(t.Context(), func(context.Context) { ran.Add(1); <-release }) {
			t.Fatal("work within the limit was dropped")
		}
	}
	if r.Go(t.Context(), func(context.Context) { t.Error("must not run") }) {
		t.Fatal("work over the limit must be dropped")
	}
	close(release)
	if err := r.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !r.Go(t.Context(), func(context.Context) {}) {
		t.Fatal("capacity must come back")
	}
}

func TestWaitIsBoundedByItsContext(t *testing.T) {
	r := New(1, time.Minute)
	release := make(chan struct{})
	r.Go(t.Context(), func(context.Context) { <-release })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := r.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	close(release)
	if err := r.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestGoAfterWaitStillWorks(t *testing.T) {
	r := New(1, time.Second)
	if err := r.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !r.Go(t.Context(), func(context.Context) {}) {
		t.Fatal("dropped")
	}
}

func TestAPanickingJobIsRecoveredAndFreesItsSlot(t *testing.T) {
	r := New(1, time.Second)
	r.Go(t.Context(), func(context.Context) { panic("boom") })
	if err := r.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !r.Go(t.Context(), func(context.Context) {}) {
		t.Fatal("the slot must come back after a panic")
	}
}

func TestCloseStopsAcceptingWorkAndWaits(t *testing.T) {
	r := New(2, time.Minute)
	var done atomic.Bool
	r.Go(t.Context(), func(context.Context) { time.Sleep(50 * time.Millisecond); done.Store(true) })
	if err := r.Close(t.Context()); err != nil || !done.Load() {
		t.Fatalf("Close err=%v done=%v", err, done.Load())
	}
	if r.Go(t.Context(), func(context.Context) { t.Error("must not run") }) {
		t.Fatal("Go after Close must be dropped")
	}
}

func TestWaitDoesNotLeakAGoroutineWhenItsContextExpires(t *testing.T) {
	r := New(1, time.Minute)
	release := make(chan struct{})
	r.Go(t.Context(), func(context.Context) { <-release })
	before := runtime.NumGoroutine()
	for range 20 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		_ = r.Wait(ctx)
		cancel()
	}
	time.Sleep(20 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
	close(release)
	_ = r.Wait(t.Context())
}
