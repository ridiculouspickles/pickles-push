package relay

import (
	"strconv"
	"testing"
	"time"
)

func TestABucketAllowsABurstThenTheRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(pushBurst, pushRefill, func() time.Time { return now })

	for i := range pushBurst {
		allowed, _ := l.allow("tok")
		if !allowed {
			t.Fatalf("refused push %d of the burst", i)
		}
	}
	allowed, first := l.allow("tok")
	if allowed {
		t.Fatal("the burst is not a limit if it never runs out")
	}
	if !first {
		t.Fatal("the first refusal is what gets logged, and it did not say so")
	}
	// One line per spell of refusals, not one per refused push: they arrive at whatever
	// rate the sender chose.
	if _, again := l.allow("tok"); again {
		t.Fatal("a second refusal announced itself as the first")
	}

	// Six seconds is one token at ten a minute.
	now = now.Add(6 * time.Second)
	if allowed, _ := l.allow("tok"); !allowed {
		t.Fatal("the bucket did not refill")
	}
	if allowed, _ := l.allow("tok"); allowed {
		t.Fatal("it refilled by more than it should have")
	}
}

// A bucket is per registration. One device being flooded must not silence another.
func TestBucketsDoNotShareAcrossRegistrations(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(pushBurst, pushRefill, func() time.Time { return now })
	for range pushBurst + 5 {
		l.allow("noisy")
	}
	if allowed, _ := l.allow("quiet"); !allowed {
		t.Fatal("a flood against one token refused a push to another")
	}
}

// The map is bounded, and a full bucket is indistinguishable from one never seen — so
// forgetting it costs nothing and is what keeps a flood of distinct keys from being a
// memory leak.
func TestTheLimiterForgetsWhatHasRefilled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(pushBurst, pushRefill, func() time.Time { return now })
	for i := range limiterCapacity + 500 {
		l.allow("tok-" + strconv.Itoa(i))
	}
	l.mu.Lock()
	held := len(l.buckets)
	l.mu.Unlock()
	if held > limiterCapacity {
		t.Fatalf("the limiter is holding %d buckets, over its own ceiling", held)
	}
	// And it still limits: a key it has just been introduced to gets a burst and no
	// more.
	for range pushBurst {
		l.allow("fresh")
	}
	if allowed, _ := l.allow("fresh"); allowed {
		t.Fatal("forgetting buckets stopped the limiter limiting")
	}
}
