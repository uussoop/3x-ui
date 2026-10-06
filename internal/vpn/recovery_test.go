package vpn

import (
	"testing"
	"time"
)

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	if got := RetryDelay(0); got != 0 {
		t.Fatalf("no failures should mean no delay, got %s", got)
	}
	// A negative failure count is meaningless and must not produce a negative
	// delay, which would let a retry loop spin.
	if got := RetryDelay(-3); got != 0 {
		t.Fatalf("a negative failure count gave %s, want no delay", got)
	}
	if got, want := RetryDelay(1), RetryBaseDelay; got != want {
		t.Fatalf("first failure waits %s, want %s", got, want)
	}
	if got, want := RetryDelay(2), 2*RetryBaseDelay; got != want {
		t.Fatalf("second failure waits %s, want %s", got, want)
	}
	// Monotonic up to the cap...
	var prev time.Duration
	for f := 1; f <= 20; f++ {
		got := RetryDelay(f)
		if got < prev {
			t.Fatalf("delay shrank at %d failures: %s after %s", f, got, prev)
		}
		if got > RetryMaxDelay {
			t.Fatalf("delay %s at %d failures exceeds the cap %s", got, f, RetryMaxDelay)
		}
		prev = got
	}
	// ...and it must never reach zero again, or a long-broken tunnel starts
	// being retried on every tick.
	if got := RetryDelay(64); got != RetryMaxDelay {
		t.Fatalf("a long-broken tunnel waits %s, want the cap %s", got, RetryMaxDelay)
	}
}

func TestRetryHoldsOffThenBecomesDue(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	r := NewRetry()
	if !r.DueAt(now) {
		t.Fatal("a fresh retry must be due immediately")
	}
	r.FailAt(now)
	if r.DueAt(now) {
		t.Fatal("a retry must not be due at the instant of its failure")
	}
	if !r.DueAt(now.Add(RetryBaseDelay)) {
		t.Fatalf("a retry must be due %s after its failure", RetryBaseDelay)
	}
	// Two failures in a row must wait longer than one: restarting a broken
	// tunnel on every tick is the behaviour this exists to prevent.
	r.FailAt(now.Add(RetryBaseDelay))
	if r.DueAt(now.Add(RetryBaseDelay)) {
		t.Fatal("a retry must not be due before its second backoff elapses")
	}
	if !r.DueAt(now.Add(RetryBaseDelay + 2*RetryBaseDelay)) {
		t.Fatal("a retry must be due after the doubled backoff")
	}
	if got := r.Failures(); got != 2 {
		t.Fatalf("failures = %d, want 2", got)
	}
}

func TestRetrySuccessClearsTheBackoffImmediately(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	r := NewRetry()
	r.FailAt(now)
	r.FailAt(now)
	if r.DueAt(now) {
		t.Fatal("a tunnel with two failures must not be due yet")
	}
	// A tunnel that came up must not have to serve out a delay earned by
	// failures that no longer apply, or a legitimate config change waits
	// minutes for no reason.
	r.OKAt(now)
	if !r.DueAt(now) {
		t.Fatal("a success must make the tunnel due immediately")
	}
	if got := r.Failures(); got != 0 {
		t.Fatalf("a success left %d failures recorded", got)
	}
}