package vpn

import (
	"sync"
	"time"
)

// Retry policy for a tunnel that will not come up.
//
// The temptation with a broken tunnel is to restart it on every reconcile tick.
// That is the wrong behaviour twice over: it turns a misconfiguration into a
// restart storm (each attempt re-reads the same broken config and fails the same
// way), and, worse, it restarts the *other* tunnels too when the natural
// "recovery" is a blanket daemon restart. Both adapters therefore retry per
// tunnel, and only the tunnel that is actually failing is retried.
//
// The delay doubles per consecutive failure and is capped, so a permanently
// broken tunnel settles at one attempt per cap instead of one per tick, while a
// tunnel that fails once (a remote server restarting) is retried promptly.
const (
	// RetryBaseDelay is the delay after the first failure.
	RetryBaseDelay = 5 * time.Second
	// RetryMaxDelay caps the delay so a tunnel whose problem clears is picked
	// up reasonably quickly rather than never.
	RetryMaxDelay = 5 * time.Minute
)

// RetryDelay returns how long to wait before retrying after the given number of
// consecutive failures. Zero failures means no delay at all.
func RetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	delay := RetryBaseDelay
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= RetryMaxDelay {
			return RetryMaxDelay
		}
	}
	return delay
}

// Retry is the per-tunnel backoff state. It is safe for concurrent use and
// deliberately takes the current time from its caller rather than reading the
// clock itself, so the policy is testable without sleeping.
//
// Every method tolerates a nil receiver, which means "no failures recorded and
// no backoff". Adapters build their Retry in a struct literal, and a missing one
// must mean "retry freely" rather than panic halfway through a reconcile.
type Retry struct {
	mu       sync.Mutex
	failures int
	nextTry  time.Time
}

// NewRetry returns a Retry that is immediately due.
func NewRetry() *Retry { return &Retry{} }

// DueAt reports whether a retry is due at the given time.
func (r *Retry) DueAt(now time.Time) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !now.Before(r.nextTry)
}

// Due reports whether a retry is due now.
func (r *Retry) Due() bool { return r.DueAt(time.Now()) }

// Fail records a failed attempt and arms the backoff from now.
func (r *Retry) Fail() { r.FailAt(time.Now()) }

// FailAt records a failed attempt and arms the backoff. The next attempt is
// not due until the delay for the *new* failure count has elapsed.
func (r *Retry) FailAt(now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures++
	r.nextTry = now.Add(RetryDelay(r.failures))
}

// OK records a success, clearing the backoff.
func (r *Retry) OK() { r.OKAt(time.Now()) }

// OKAt records a success, which clears the backoff entirely: a tunnel that came
// up must be eligible for the next change immediately, not after the delay its
// previous failure earned.
func (r *Retry) OKAt(_ time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
	r.nextTry = time.Time{}
}

// Failures returns the number of consecutive failures recorded.
func (r *Retry) Failures() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures
}
