package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/benfultz/proto-ct/internal/domainpb"
	"golang.org/x/time/rate"
)

// ── circuit breaker ──────────────────────────────────────────────────────────

type circuitBreaker struct {
	mu        sync.Mutex
	threshold float64
	ring      []bool
	pos       int
	errCount  int
	tripped   bool
	tripUntil time.Time
}

func newCircuitBreaker(threshold float64, window int) *circuitBreaker {
	return &circuitBreaker{threshold: threshold, ring: make([]bool, window)}
}

func (cb *circuitBreaker) record(isErr bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.ring[cb.pos] {
		cb.errCount--
	}
	cb.ring[cb.pos] = isErr
	if isErr {
		cb.errCount++
	}
	cb.pos = (cb.pos + 1) % len(cb.ring)
	errRate := float64(cb.errCount) / float64(len(cb.ring))
	if errRate > cb.threshold && !cb.tripped {
		cb.tripped = true
		cb.tripUntil = time.Now().Add(30 * time.Second)
		log.Printf("circuit breaker tripped (%.0f%% errors in last %d requests), pausing 30s",
			errRate*100, len(cb.ring))
	} else if cb.tripped && time.Now().After(cb.tripUntil) {
		cb.tripped = false
	}
}

func (cb *circuitBreaker) wait(ctx context.Context) {
	cb.mu.Lock()
	if !cb.tripped {
		cb.mu.Unlock()
		return
	}
	remaining := time.Until(cb.tripUntil)
	cb.mu.Unlock()
	if remaining > 0 {
		select {
		case <-time.After(remaining):
		case <-ctx.Done():
		}
	}
}

func (cb *circuitBreaker) state() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.tripped {
		return fmt.Sprintf("TRIPPED(resume in %s)", time.Until(cb.tripUntil).Round(time.Second))
	}
	return fmt.Sprintf("ok(%.1f%%err)", 100*float64(cb.errCount)/float64(len(cb.ring)))
}

// ── workers ──────────────────────────────────────────────────────────────────

func runWorker(ctx context.Context, workCh <-chan workItem, resultCh chan<- resultItem,
	client domainpb.ResolverClient, lim *rate.Limiter, cb *circuitBreaker,
	timeout time.Duration, st *runStats) {
	for {
		select {
		case item, ok := <-workCh:
			if !ok {
				return
			}
			cb.wait(ctx)
			if ctx.Err() != nil {
				return
			}
			lim.Wait(ctx) //nolint:errcheck — only fails on ctx cancel, checked next
			if ctx.Err() != nil {
				return
			}
			res := resolve(ctx, client, item, timeout)
			st.record(res.status)
			cb.record(res.status == "error") // timeouts are slow servers, not abuse signals
			select {
			case resultCh <- res:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// resolve calls GetDNSRecords with retries. Transient errors retry up to 3
// times with exponential backoff+jitter; timeouts retry once.
func resolve(parentCtx context.Context, client domainpb.ResolverClient, item workItem, timeout time.Duration) resultItem {
	backoff := 2 * time.Second
	timeoutAttempts := 0

	for attempt := 0; attempt < 4; attempt++ {
		if parentCtx.Err() != nil {
			break
		}
		if attempt > 0 {
			jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
			timer := time.NewTimer(backoff + jitter)
			select {
			case <-timer.C:
			case <-parentCtx.Done():
				timer.Stop()
				break
			}
			backoff *= 2
		}
		if parentCtx.Err() != nil {
			break
		}

		tctx, cancel := context.WithTimeout(parentCtx, timeout)
		res, retry := doResolve(tctx, item, client)
		cancel()

		if !retry {
			return res
		}
		if res.status == "timeout" {
			timeoutAttempts++
			if timeoutAttempts >= 2 {
				return res
			}
		}
	}
	return resultItem{domain: item.domain, shard: item.shard, status: "error", fetchedAt: time.Now().Unix()}
}

// doResolve makes a single GetDNSRecords call and returns the result plus
// whether the caller should retry.
func doResolve(ctx context.Context, item workItem, client domainpb.ResolverClient) (resultItem, bool) {
	now := time.Now().Unix()
	base := resultItem{domain: item.domain, shard: item.shard, fetchedAt: now}

	stream, err := client.GetDNSRecords(ctx, &domainpb.Domain{Hostname: item.domain})
	if err != nil {
		base.status = "error"
		return base, true
	}

	var records []recordRow
	for {
		rec, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				base.status = "timeout"
			} else {
				base.status = "error"
			}
			return base, true
		}
		rdata := rec.GetText()
		if rdata == "" {
			if raw := rec.GetRaw(); len(raw) > 0 {
				rdata = fmt.Sprintf("0x%x", raw)
			}
		}
		if rdata == "" {
			continue
		}
		records = append(records, recordRow{
			recordType: rec.GetType().String(),
			ttl:        rec.GetTtlSeconds(),
			rdata:      rdata,
		})
	}

	if len(records) == 0 {
		base.status = "nxdomain"
		return base, false
	}
	base.status = "ok"
	base.records = records
	return base, false
}
