package relay

import (
	"sync"
	"time"
)

// Rate limiting, and why a relay that forwards opaque bytes needs any.
//
// The edge cannot do this. Apache sees a URL whose only meaningful part is a delivery
// token it must not log, and the Gmail endpoint is one path for every subscriber — so
// "per token" and "per address" are limits only this program can express
// (pickles-email#464).
//
// Everything here is per delivery token, checked in `deliver`, which is the single
// place both the JMAP and the Gmail paths pass through. A token is a bearer capability:
// whoever holds one can wake one device, and the point of the bucket is that they cannot
// wake it all night.

const (
	// pushBurst is how many pushes to one device may arrive at once.
	//
	// Generous on purpose: a mailbox that has been offline can genuinely produce a
	// handful of StateChanges in a second when it reconnects, and the cost of being
	// wrong in this direction is a notification nobody gets.
	pushBurst = 20
	// pushRefill is the sustained rate, in pushes per second — ten a minute.
	//
	// A real mailbox does not sustain ten notifications a minute for long, and the
	// device coalesces anyway. Someone holding a leaked token, or a provider stuck in a
	// retry loop, does: the stale Pub/Sub subscription on 2026-09-12 was climbing
	// through 42 messages a minute when it was found.
	pushRefill = 10.0 / 60.0
	// limiterCapacity is how many delivery tokens we are willing to remember at once.
	//
	// Deliberately above store.DefaultMaxRegistrations: a push only reaches the limiter
	// if its token is in the store, so in ordinary running there is a bucket per
	// registration and this ceiling is never approached. It is here so that a site
	// configured with a larger store, or one being flooded across many real tokens, has
	// a bound rather than a leak. Full buckets go first, and a full bucket is
	// indistinguishable from one never seen, so forgetting it costs nothing.
	limiterCapacity = 8192
)

type bucket struct {
	tokens float64
	last   time.Time
	// announced stops one line per refused push. The refusals arrive at whatever rate
	// the sender chose, so logging each one hands them the log as well.
	announced bool
}

// limiter is a token bucket per key.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   float64
	refill  float64
	now     func() time.Time
}

func newLimiter(burst, refill float64, now func() time.Time) *limiter {
	if now == nil {
		now = time.Now
	}
	return &limiter{buckets: map[string]*bucket{}, burst: burst, refill: refill, now: now}
}

// allow takes one token if there is one. The second return is true the first time a key
// is refused, and false while it stays refused, so a caller can log the transition.
func (l *limiter) allow(key string) (bool, bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= limiterCapacity {
			l.forgetFullLocked(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.refill
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		first := !b.announced
		b.announced = true
		return false, first
	}
	b.tokens--
	b.announced = false
	if b.tokens >= l.burst {
		// Full again, and a full bucket is what a stranger gets anyway.
		delete(l.buckets, key)
	}
	return true, false
}

// forgetFullLocked drops every bucket that has refilled. If that frees nothing — which
// means the map is genuinely full of active senders — the oldest go instead, because a
// map that cannot grow must still accept the device that has just come back.
func (l *limiter) forgetFullLocked(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.refill >= l.burst {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) < limiterCapacity {
		return
	}
	// Nothing had refilled, so the map is full of senders that are all being limited
	// right now. One has to go, and the least recently seen is the least interesting —
	// but it has to be chosen by taking the first and comparing, not by comparing
	// against `now`: when every bucket was touched in the same instant none is *before*
	// now, and a limiter that then evicts nothing grows without a ceiling.
	var victim string
	var oldest time.Time
	for key, b := range l.buckets {
		if victim == "" || b.last.Before(oldest) {
			victim, oldest = key, b.last
		}
	}
	delete(l.buckets, victim)
}
