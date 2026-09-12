package relay

import (
	"errors"
	"sync"
)

// Delivery runs off the request goroutine, a bounded number at a time.
//
// Two reasons, and they are different (pickles-email#464):
//
//   - **The provider is not waiting for Apple.** A push used to run inside the handler,
//     on the request's context, so a JMAP server whose own timeout is shorter than the
//     APNs client's twenty seconds cancelled the push it had just asked for — and then
//     retried, which is the duplicate notification the whole design is arranged to
//     avoid. One Gmail Pub/Sub message fans out to every device reading that address,
//     each a synchronous POST, inside a handler Pub/Sub redelivers after its ack
//     deadline.
//   - **Apple is not waiting for us.** Without a ceiling, a flood of pushes is a flood
//     of concurrent connections to APNs with our team's key on them, and the throttling
//     that follows is not confined to whoever caused it.
const (
	// apnsWorkers is how many pushes may be in flight to Apple at once, across every
	// registration this site serves.
	apnsWorkers = 8
	// queueDepth is how many may wait. Past it a push is dropped rather than queued: a
	// notification delivered ten minutes late is worse than one never delivered, and
	// the device syncs when it is next opened regardless.
	queueDepth = 1024
)

// Why a submission fails, which is worth distinguishing: full is a site under load and
// closed is a site shutting down, and only one of them is a reason to look at anything.
var (
	errQueueFull   = errors.New("full")
	errQueueClosed = errors.New("closed")
)

type deliveryQueue struct {
	jobs chan func()
	// mu guards closed, and is held across the non-blocking send so that a handler
	// still running while the process shuts down cannot send on a closed channel.
	mu     sync.Mutex
	closed bool
	// wg counts what has been submitted and not yet finished. Shutdown waits on it, and
	// so do the tests, which is what keeps them asserting on the real path rather than
	// on a second one kept synchronous for their benefit.
	wg sync.WaitGroup
}

func newDeliveryQueue(workers, depth int) *deliveryQueue {
	q := &deliveryQueue{jobs: make(chan func(), depth)}
	for range workers {
		go func() {
			for job := range q.jobs {
				job()
				q.wg.Done()
			}
		}()
	}
	return q
}

// submit queues work, or reports that the queue is full. It never blocks: the caller is
// a request handler, and making a provider wait for our backlog is how a backlog turns
// into a retry storm.
func (q *deliveryQueue) submit(job func()) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errQueueClosed
	}
	q.wg.Add(1)
	select {
	case q.jobs <- job:
		return nil
	default:
		q.wg.Done()
		return errQueueFull
	}
}

// wait blocks until everything submitted so far has run.
func (q *deliveryQueue) wait() { q.wg.Wait() }

func (q *deliveryQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	close(q.jobs)
}
