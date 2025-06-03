// Package pkg provides a pipeline architecture for processing AWS key discoveries
package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/go-github/github"
)

// FileDiscovery represents a discovered file that might contain AWS keys
type FileDiscovery struct {
	File     *github.CodeResult
	Content  string
	Priority float64 // Higher = more likely to contain keys
}

// KeyCandidate represents a potential AWS key pair found in content
type KeyCandidateEnhanced struct {
	KeyCandidate
	File     *github.CodeResult
	Priority float64
}

// ValidationJob represents a batch of keys to validate
type ValidationJob struct {
	Candidates []KeyCandidateEnhanced
	Callback   func([]AWSKeyFinding, error)
}

// Pipeline processes discoveries through multiple stages
type Pipeline struct {
	// Channels for each stage
	discoveries    chan FileDiscovery
	filteredKeys   chan KeyCandidateEnhanced
	validationJobs chan ValidationJob
	validatedKeys  chan AWSKeyFinding

	// Components
	keyExtractor    *ContextualKeyExtractor
	keyStorage      *KeyStorage
	validator       *BatchValidator
	repoScorer      *RepositoryScorer
	configParsers   map[string]ConfigParser
	deduplicator    *DeduplicationManager

	// Pipeline control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Configuration
	config PipelineConfig
}

type PipelineConfig struct {
	// Worker pool sizes
	DiscoveryWorkers  int
	FilterWorkers     int
	ValidationWorkers int
	StorageWorkers    int

	// Batch sizes
	ValidationBatchSize int
	ValidationTimeout   time.Duration

	// Buffer sizes
	DiscoveryBuffer  int
	FilterBuffer     int
	ValidationBuffer int
	StorageBuffer    int
}

// NewPipeline creates a new processing pipeline
func NewPipeline(keyStorage *KeyStorage, config PipelineConfig) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())

	return &Pipeline{
		discoveries:    make(chan FileDiscovery, config.DiscoveryBuffer),
		filteredKeys:   make(chan KeyCandidateEnhanced, config.FilterBuffer),
		validationJobs: make(chan ValidationJob, config.ValidationBuffer),
		validatedKeys:  make(chan AWSKeyFinding, config.StorageBuffer),

		keyExtractor:  NewContextualKeyExtractor(),
		keyStorage:    keyStorage,
		validator:     NewBatchValidator(),
		repoScorer:    NewRepositoryScorer(),
		configParsers: initConfigParsers(),
		deduplicator:  NewDeduplicationManager(DefaultDeduplicationConfig()),

		ctx:    ctx,
		cancel: cancel,
		config: config,
	}
}

// Start begins processing the pipeline
func (p *Pipeline) Start() {
	log.Println("🚀 Starting processing pipeline...")

	// Start worker pools for each stage
	p.startDiscoveryWorkers()
	p.startFilterWorkers()
	p.startValidationWorkers()
	p.startStorageWorkers()

	log.Printf("✅ Pipeline started with %d discovery, %d filter, %d validation, %d storage workers",
		p.config.DiscoveryWorkers, p.config.FilterWorkers,
		p.config.ValidationWorkers, p.config.StorageWorkers)
}

// Stop gracefully shuts down the pipeline
func (p *Pipeline) Stop() {
	log.Println("🛑 Stopping pipeline...")
	p.cancel()

	// Close input channels to trigger graceful shutdown
	close(p.discoveries)

	// Wait for all workers to finish
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("✅ Pipeline stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("⚠️  Pipeline stop timed out")
	}
}

// SubmitDiscovery adds a file discovery to the pipeline
func (p *Pipeline) SubmitDiscovery(file *github.CodeResult, content string) {
	priority := p.repoScorer.ScoreFile(file, content)
	
	discovery := FileDiscovery{
		File:     file,
		Content:  content,
		Priority: priority,
	}

	select {
	case p.discoveries <- discovery:
		// Successfully queued
	case <-p.ctx.Done():
		// Pipeline is shutting down
	default:
		// Buffer full, log warning
		log.Printf("⚠️  Discovery buffer full, dropping file: %s", file.GetPath())
	}
}

// Stage 1: Discovery Workers - Extract keys from file content
func (p *Pipeline) startDiscoveryWorkers() {
	for i := 0; i < p.config.DiscoveryWorkers; i++ {
		p.wg.Add(1)
		go func(workerID int) {
			defer p.wg.Done()
			p.discoveryWorker(workerID)
		}(i)
	}
}

func (p *Pipeline) discoveryWorker(workerID int) {
	log.Printf("🔍 Discovery worker %d started", workerID)
	defer log.Printf("🔍 Discovery worker %d stopped", workerID)

	for {
		select {
		case discovery, ok := <-p.discoveries:
			if !ok {
				// Channel closed, start shutdown
				close(p.filteredKeys)
				return
			}

			// Extract keys from content
			candidates := p.extractKeysFromDiscovery(discovery)
			
			// Send candidates to filtering stage
			for _, candidate := range candidates {
				enhanced := KeyCandidateEnhanced{
					KeyCandidate: candidate,
					File:         discovery.File,
					Priority:     discovery.Priority + candidate.Confidence,
				}

				select {
				case p.filteredKeys <- enhanced:
					// Successfully sent to filter stage
				case <-p.ctx.Done():
					return
				}
			}

		case <-p.ctx.Done():
			return
		}
	}
}

// Stage 2: Filter Workers - Apply confidence thresholds and deduplication
func (p *Pipeline) startFilterWorkers() {
	for i := 0; i < p.config.FilterWorkers; i++ {
		p.wg.Add(1)
		go func(workerID int) {
			defer p.wg.Done()
			p.filterWorker(workerID)
		}(i)
	}
}

func (p *Pipeline) filterWorker(workerID int) {
	log.Printf("🔧 Filter worker %d started", workerID)
	defer log.Printf("🔧 Filter worker %d stopped", workerID)

	batch := make([]KeyCandidateEnhanced, 0, p.config.ValidationBatchSize)
	batchTimer := time.NewTimer(p.config.ValidationTimeout)
	defer batchTimer.Stop()

	flushBatch := func() {
		if len(batch) > 0 {
			job := ValidationJob{
				Candidates: make([]KeyCandidateEnhanced, len(batch)),
				Callback:   p.handleValidationResults,
			}
			copy(job.Candidates, batch)

			select {
			case p.validationJobs <- job:
				batch = batch[:0] // Reset batch
			case <-p.ctx.Done():
				return
			}
		}
	}

	for {
		select {
		case candidate, ok := <-p.filteredKeys:
			if !ok {
				// Channel closed, flush final batch and shutdown
				flushBatch()
				close(p.validationJobs)
				return
			}

			// Apply confidence threshold
			const minConfidence = 0.7
			if candidate.Priority >= minConfidence {
				batch = append(batch, candidate)

				// Flush batch if full
				if len(batch) >= p.config.ValidationBatchSize {
					flushBatch()
					batchTimer.Reset(p.config.ValidationTimeout)
				}
			}

		case <-batchTimer.C:
			// Timeout reached, flush current batch
			flushBatch()
			batchTimer.Reset(p.config.ValidationTimeout)

		case <-p.ctx.Done():
			return
		}
	}
}

// Stage 3: Validation Workers - Batch validate AWS keys
func (p *Pipeline) startValidationWorkers() {
	for i := 0; i < p.config.ValidationWorkers; i++ {
		p.wg.Add(1)
		go func(workerID int) {
			defer p.wg.Done()
			p.validationWorker(workerID)
		}(i)
	}
}

func (p *Pipeline) validationWorker(workerID int) {
	log.Printf("✅ Validation worker %d started", workerID)
	defer log.Printf("✅ Validation worker %d stopped", workerID)

	for {
		select {
		case job, ok := <-p.validationJobs:
			if !ok {
				// Channel closed, start shutdown
				close(p.validatedKeys)
				return
			}

			// Process validation job
			results, err := p.validator.ValidateBatch(p.ctx, job.Candidates)
			job.Callback(results, err)

		case <-p.ctx.Done():
			return
		}
	}
}

// Stage 4: Storage Workers - Save validated keys
func (p *Pipeline) startStorageWorkers() {
	for i := 0; i < p.config.StorageWorkers; i++ {
		p.wg.Add(1)
		go func(workerID int) {
			defer p.wg.Done()
			p.storageWorker(workerID)
		}(i)
	}
}

func (p *Pipeline) storageWorker(workerID int) {
	log.Printf("💾 Storage worker %d started", workerID)
	defer log.Printf("💾 Storage worker %d stopped", workerID)

	for {
		select {
		case finding, ok := <-p.validatedKeys:
			if !ok {
				// Channel closed, shutdown
				return
			}

			// Analyze for duplicates before storing
			analysis := p.deduplicator.AnalyzeFinding(&finding)
			
			if analysis.IsDuplicate {
				log.Printf("🔍 Duplicate analysis: %s (confidence: %.2f, type: %s)", 
					analysis.RecommendedAction, analysis.Confidence, analysis.DuplicateType)
				
				switch analysis.RecommendedAction {
				case "skip":
					log.Printf("⏭️  Skipping duplicate finding: %s", finding.AccessKey)
					continue
					
				case "update":
					log.Printf("🔄 Updating existing finding with new information")
					// Update the original finding with any new information
					p.updateExistingFinding(analysis.OriginalFinding, &finding)
					continue
					
				case "keep-both":
					log.Printf("📌 Keeping both findings (sufficiently different)")
					// Fall through to normal storage
				}
			}
			
			// Store the validated finding
			if err := p.keyStorage.AddFinding(finding); err != nil {
				log.Printf("❌ Error storing finding: %v", err)
			} else {
				log.Printf("✅ Stored valid key: %s (Account: %s)", 
					finding.AccessKey, finding.AccountID)
				
				// Add to deduplication tracking
				p.deduplicator.AddFinding(&finding)
				
				// Send Discord alert
				go sendDiscordAlert(finding.Repository, finding.FileURL, []string{finding.AccessKey})
			}

		case <-p.ctx.Done():
			return
		}
	}
}

// Helper functions
func (p *Pipeline) extractKeysFromDiscovery(discovery FileDiscovery) []KeyCandidate {
	// Use appropriate parser based on file type
	if parser, exists := p.configParsers[getFileExtension(discovery.File.GetPath())]; exists {
		return parser.ExtractCredentials([]byte(discovery.Content))
	}

	// Fall back to contextual extraction
	return p.keyExtractor.ExtractKeysWithContext(discovery.Content)
}

func (p *Pipeline) handleValidationResults(results []AWSKeyFinding, err error) {
	if err != nil {
		log.Printf("❌ Batch validation error: %v", err)
		return
	}

	// Send valid findings to storage
	for _, finding := range results {
		select {
		case p.validatedKeys <- finding:
			// Successfully queued for storage
		case <-p.ctx.Done():
			return
		default:
			log.Printf("⚠️  Storage buffer full, dropping finding: %s", finding.AccessKey)
		}
	}
}

// getFileExtension extracts file extension for parser selection
func getFileExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' {
			break
		}
	}
	return ""
}

// DefaultPipelineConfig returns sensible defaults for pipeline configuration
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		DiscoveryWorkers:    4,
		FilterWorkers:       2,
		ValidationWorkers:   3,
		StorageWorkers:      1,
		ValidationBatchSize: 10,
		ValidationTimeout:   5 * time.Second,
		DiscoveryBuffer:     100,
		FilterBuffer:        200,
		ValidationBuffer:    50,
		StorageBuffer:       100,
	}
}

// sendDiscordAlert sends an alert to Discord webhook
func sendDiscordAlert(repo, url string, keys []string) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL == "" {
		return // No webhook configured
	}
	
	message := map[string]string{
		"content": fmt.Sprintf("🚨 AWS Key Leak Detected!\nRepo: %s\nURL: %s\nKeys: %v", repo, url, keys),
	}
	jsonData, _ := json.Marshal(message)

	req, _ := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending alert to Discord: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Println("🚨 Alert sent to Discord successfully!")
}

// updateExistingFinding merges new information into an existing finding
func (p *Pipeline) updateExistingFinding(existing, new *AWSKeyFinding) {
	// Update with any new information that's missing or more recent
	if existing.AccountID == "" && new.AccountID != "" {
		existing.AccountID = new.AccountID
	}
	if existing.UserName == "" && new.UserName != "" {
		existing.UserName = new.UserName
	}
	if existing.ARN == "" && new.ARN != "" {
		existing.ARN = new.ARN
	}
	
	// Merge permissions (keep unique ones)
	for _, perm := range new.Permissions {
		found := false
		for _, existingPerm := range existing.Permissions {
			if existingPerm == perm {
				found = true
				break
			}
		}
		if !found {
			existing.Permissions = append(existing.Permissions, perm)
		}
	}
	
	// Update validation timestamp
	existing.ValidatedAt = new.ValidatedAt
	
	log.Printf("🔄 Updated existing finding with new information from %s", new.Repository)
}

// GetDeduplicationStats returns deduplication statistics
func (p *Pipeline) GetDeduplicationStats() map[string]interface{} {
	if p.deduplicator != nil {
		return p.deduplicator.GetDuplicationStats()
	}
	return map[string]interface{}{}
}

// GetAccountGroups returns account-grouped findings
func (p *Pipeline) GetAccountGroups() []*AccountGroup {
	if p.deduplicator != nil {
		return p.deduplicator.GetAccountGroups()
	}
	return []*AccountGroup{}
}