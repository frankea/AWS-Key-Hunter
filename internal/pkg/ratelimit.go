// Package pkg provides rate limiting functionality for GitHub API requests
package pkg

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/go-github/github"
)

// RateLimiter manages API request rate limiting with exponential backoff
type RateLimiter struct {
	mu              sync.Mutex
	requestsPerHour int
	requestCount    int
	windowStart     time.Time
	backoffUntil    time.Time
	backoffDuration time.Duration
}

// NewRateLimiter creates a new rate limiter with the specified requests per hour limit
func NewRateLimiter(requestsPerHour int) *RateLimiter {
	return &RateLimiter{
		requestsPerHour: requestsPerHour,
		windowStart:     time.Now(),
		backoffDuration: time.Second * 30, // Start with 30s backoff
	}
}

// CheckRateLimit checks GitHub rate limit from response
func (rl *RateLimiter) CheckRateLimit(resp *github.Response) {
	if resp == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check rate limit headers
	if resp.Rate.Remaining == 0 {
		resetTime := time.Unix(int64(resp.Rate.Reset.Time.Unix()), 0)
		rl.backoffUntil = resetTime.Add(time.Minute) // Add buffer
		log.Printf("⚠️  Rate limit exhausted. Reset at: %s", resetTime.Format("15:04:05"))
	}

	// Log current rate limit status
	if resp.Rate.Limit > 0 {
		log.Printf("📊 Rate limit: %d/%d remaining, resets at %s",
			resp.Rate.Remaining,
			resp.Rate.Limit,
			resp.Rate.Reset.Time.Format("15:04:05"))
	}
}

// WaitIfNeeded blocks if we need to wait for rate limit
func (rl *RateLimiter) WaitIfNeeded() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if we're in backoff period
	if time.Now().Before(rl.backoffUntil) {
		waitDuration := time.Until(rl.backoffUntil)
		log.Printf("⏳ Rate limited. Waiting %v before next request", waitDuration.Round(time.Second))

		// Countdown timer
		for remaining := waitDuration; remaining > 0; remaining -= 5 * time.Second {
			if remaining <= 5*time.Second {
				time.Sleep(remaining)
				break
			}
			time.Sleep(5 * time.Second)
			remaining = time.Until(rl.backoffUntil)
			if remaining > 0 {
				log.Printf("⏱️  Rate limit: %v remaining...", remaining.Round(time.Second))
			}
		}
	}

	// Check our own rate limiting
	elapsed := time.Since(rl.windowStart)
	if elapsed > time.Hour {
		// Reset window
		rl.requestCount = 0
		rl.windowStart = time.Now()
	}

	// Calculate if we need to slow down
	if rl.requestCount >= rl.requestsPerHour {
		waitTime := time.Hour - elapsed
		log.Printf("⏳ Approaching rate limit. Waiting %v", waitTime.Round(time.Second))

		// Countdown timer for long waits
		if waitTime > 10*time.Second {
			for remaining := waitTime; remaining > 0; remaining -= 10 * time.Second {
				if remaining <= 10*time.Second {
					time.Sleep(remaining)
					break
				}
				time.Sleep(10 * time.Second)
				remaining = time.Hour - time.Since(rl.windowStart)
				if remaining > 0 {
					log.Printf("⏱️  Rate limit reset: %v remaining...", remaining.Round(time.Second))
				}
			}
		} else {
			time.Sleep(waitTime)
		}

		rl.requestCount = 0
		rl.windowStart = time.Now()
	}

	rl.requestCount++
	return nil
}

// HandleError processes errors and applies backoff
func (rl *RateLimiter) HandleError(err error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rateLimitErr, ok := err.(*github.RateLimitError); ok {
		// GitHub rate limit error
		if !rateLimitErr.Rate.Reset.Time.IsZero() {
			rl.backoffUntil = rateLimitErr.Rate.Reset.Time.Add(time.Minute)
			log.Printf("🛑 Rate limit error. Will retry after %s", rl.backoffUntil.Format("15:04:05"))
		}
		// Exponential backoff
		rl.backoffDuration = rl.backoffDuration * 2
		if rl.backoffDuration > time.Hour {
			rl.backoffDuration = time.Hour
		}
	} else if _, ok := err.(*github.AbuseRateLimitError); ok {
		// Abuse rate limit (secondary rate limit)
		log.Printf("🛑 Abuse rate limit triggered. Backing off for %v", rl.backoffDuration)
		rl.backoffUntil = time.Now().Add(rl.backoffDuration)
		rl.backoffDuration = rl.backoffDuration * 2
	}
}

// ResetBackoff resets the backoff duration after successful requests
func (rl *RateLimiter) ResetBackoff() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.backoffDuration = time.Second * 30
}

// RetryWithBackoff retries a function with exponential backoff
func RetryWithBackoff(ctx context.Context, maxRetries int, fn func() error) error {
	backoff := time.Second

	for i := 0; i < maxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}

		if i < maxRetries-1 {
			log.Printf("🔄 Retry %d/%d after error: %v", i+1, maxRetries, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > time.Minute*5 {
					backoff = time.Minute * 5
				}
			}
		}
	}

	return fmt.Errorf("max retries (%d) exceeded", maxRetries)
}
