package handlers

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// allocateRPS caps each client identity to one /allocate per second on
// average, with a small burst. /allocate is anonymous, KMS-signs per call,
// and triggers a TEE session — without a cap a single spammer can drive
// KMS cost and tie up TEE resources. The router runs as a single Cloud Run
// instance at a time, so an in-memory map is sufficient.
const (
	allocateRPS       = rate.Limit(1) // tokens per second per IP
	allocateBurst     = 3             // burst tolerance
	rateLimiterMaxLen = 4096          // hard cap on the limiter map size; oldest entries evicted
	rateLimiterTTL    = 10 * time.Minute
)

// ipRateLimiter is an in-memory per-IP token bucket. Concurrency-safe.
// Entries are evicted lazily when accessed past TTL or when the map exceeds
// rateLimiterMaxLen (whichever comes first).
type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*ipBucket
	limit    rate.Limit
	burst    int
	ttl      time.Duration
	maxSize  int
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(limit rate.Limit, burst int, ttl time.Duration, maxSize int) *ipRateLimiter {
	return &ipRateLimiter{
		buckets: make(map[string]*ipBucket),
		limit:   limit,
		burst:   burst,
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Allow reports whether the IP may proceed. Updates lastSeen on every call,
// so a steady stream of allowed requests keeps the bucket warm.
func (l *ipRateLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= l.maxSize {
			l.evictOldestLocked(now)
		}
		b = &ipBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[ip] = b
	} else if now.Sub(b.lastSeen) > l.ttl {
		// Bucket is stale; reset so a returning client doesn't carry over
		// hours-old token state.
		b.limiter = rate.NewLimiter(l.limit, l.burst)
	}
	b.lastSeen = now
	return b.limiter.Allow()
}

// evictOldestLocked removes the single oldest entry to make room. Cheap
// enough at maxSize=4096; if this ever shows up in pprof, swap for a heap.
func (l *ipRateLimiter) evictOldestLocked(_ time.Time) {
	var oldestKey string
	var oldestSeen time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.lastSeen.Before(oldestSeen) {
			oldestKey = k
			oldestSeen = b.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

// trustedProxyHops is how many trailing X-Forwarded-For entries the GCP
// HTTPS LB writes itself: "<client-supplied>, <client-ip>, <lb-ip>".
const trustedProxyHops = 2

// Only the last two XFF entries are LB-written; keying on the caller-supplied
// leftmost one mints a fresh full burst per request. Falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) >= trustedProxyHops {
			if vouched := strings.TrimSpace(parts[len(parts)-trustedProxyHops]); vouched != "" {
				if ip := net.ParseIP(vouched); ip != nil {
					return ip.String()
				}
				return vouched
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
