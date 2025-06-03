// Package pkg provides goroutine supervision and management capabilities
package pkg

import (
	"context"
	"log"
	"sync"
	"time"
)

// WorkerFunc is a function that does work and should be supervised
type WorkerFunc func(ctx context.Context) error

// Supervisor manages goroutines with health checks and restart capability
type Supervisor struct {
	workers map[string]*Worker
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Worker represents a supervised goroutine
type Worker struct {
	name         string
	fn           WorkerFunc
	restartDelay time.Duration
	maxRestarts  int
	restartCount int
	lastHealthy  time.Time
	lastError    error
	isRunning    bool
	mu           sync.Mutex
}

// NewSupervisor creates a new goroutine supervisor
func NewSupervisor() *Supervisor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{
		workers: make(map[string]*Worker),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// AddWorker adds a new worker to supervise
func (s *Supervisor) AddWorker(name string, fn WorkerFunc, restartDelay time.Duration, maxRestarts int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workers[name] = &Worker{
		name:         name,
		fn:           fn,
		restartDelay: restartDelay,
		maxRestarts:  maxRestarts,
		lastHealthy:  time.Now(),
	}
}

// Start begins supervising all workers
func (s *Supervisor) Start() {
	s.mu.RLock()
	workers := make([]*Worker, 0, len(s.workers))
	for _, w := range s.workers {
		workers = append(workers, w)
	}
	s.mu.RUnlock()

	for _, worker := range workers {
		s.wg.Add(1)
		go s.superviseWorker(worker)
	}

	// Start health check monitor
	s.wg.Add(1)
	go s.healthMonitor()
}

// superviseWorker monitors and restarts a worker as needed
func (s *Supervisor) superviseWorker(w *Worker) {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("🛑 Stopping worker: %s", w.name)
			return
		default:
			w.mu.Lock()
			if w.restartCount >= w.maxRestarts {
				log.Printf("❌ Worker %s exceeded max restarts (%d). Stopping.", w.name, w.maxRestarts)
				w.mu.Unlock()
				return
			}
			w.isRunning = true
			w.lastHealthy = time.Now()
			w.mu.Unlock()

			log.Printf("🚀 Starting worker: %s (restart #%d)", w.name, w.restartCount)

			// Run the worker
			err := w.fn(s.ctx)

			w.mu.Lock()
			w.isRunning = false
			w.lastError = err

			if err != nil {
				log.Printf("⚠️  Worker %s crashed: %v", w.name, err)
				w.restartCount++
				w.mu.Unlock()

				// Wait before restarting
				select {
				case <-s.ctx.Done():
					return
				case <-time.After(w.restartDelay):
					continue
				}
			} else {
				// Worker exited cleanly
				log.Printf("✅ Worker %s exited cleanly", w.name)
				w.mu.Unlock()
				return
			}
		}
	}
}

// healthMonitor periodically checks worker health
func (s *Supervisor) healthMonitor() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkHealth()
		}
	}
}

// checkHealth logs the health status of all workers
func (s *Supervisor) checkHealth() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	log.Println("📊 Worker Health Check:")
	for name, w := range s.workers {
		w.mu.Lock()
		status := "stopped"
		if w.isRunning {
			status = "running"
		}

		timeSinceHealthy := time.Since(w.lastHealthy)
		log.Printf("  - %s: %s (last healthy: %v ago, restarts: %d/%d)",
			name, status, timeSinceHealthy.Round(time.Second),
			w.restartCount, w.maxRestarts)

		if w.lastError != nil {
			log.Printf("    Last error: %v", w.lastError)
		}
		w.mu.Unlock()
	}
}

// Stop gracefully shuts down all workers
func (s *Supervisor) Stop() {
	log.Println("🛑 Stopping supervisor...")
	s.cancel()

	// Give workers a grace period to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("✅ All workers stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Println("⚠️  Force stopping after timeout")
	}
}

// GetWorkerStatus returns the status of a specific worker
func (s *Supervisor) GetWorkerStatus(name string) (isRunning bool, restartCount int, lastError error) {
	s.mu.RLock()
	w, exists := s.workers[name]
	s.mu.RUnlock()

	if !exists {
		return false, 0, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	return w.isRunning, w.restartCount, w.lastError
}
