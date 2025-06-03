// Package pkg provides batch validation functionality for AWS keys
package pkg

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ValidationResult represents the result of validating a single key
type ValidationResult struct {
	Candidate   KeyCandidateEnhanced
	IsValid     bool
	AccountInfo AWSAccountInfo
	Error       error
}

// BatchValidator efficiently validates multiple AWS keys in parallel
type BatchValidator struct {
	// Validation cache to avoid re-validating same keys
	cache     map[string]*CachedValidation
	cacheMu   sync.RWMutex
	
	// Rate limiting for AWS API calls
	awsRateLimit chan struct{}
	
	// Configuration
	maxConcurrent int
	cacheTimeout  time.Duration
}

// CachedValidation stores previous validation results
type CachedValidation struct {
	Result    ValidationResult
	Timestamp time.Time
}

// NewBatchValidator creates a new batch validator
func NewBatchValidator() *BatchValidator {
	const maxConcurrentAWSCalls = 5 // Conservative limit for AWS API
	
	return &BatchValidator{
		cache:         make(map[string]*CachedValidation),
		awsRateLimit:  make(chan struct{}, maxConcurrentAWSCalls),
		maxConcurrent: maxConcurrentAWSCalls,
		cacheTimeout:  1 * time.Hour, // Cache validation results for 1 hour
	}
}

// ValidateBatch validates multiple key candidates in parallel
func (bv *BatchValidator) ValidateBatch(ctx context.Context, candidates []KeyCandidateEnhanced) ([]AWSKeyFinding, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	log.Printf("🔍 Validating batch of %d key candidates", len(candidates))
	
	// Check cache first and separate cached vs uncached
	uncachedCandidates := make([]KeyCandidateEnhanced, 0, len(candidates))
	cachedResults := make([]ValidationResult, 0, len(candidates))
	
	bv.cacheMu.RLock()
	for _, candidate := range candidates {
		cacheKey := candidate.AccessKey + ":" + candidate.SecretKey
		if cached, exists := bv.cache[cacheKey]; exists {
			if time.Since(cached.Timestamp) < bv.cacheTimeout {
				cachedResults = append(cachedResults, cached.Result)
				continue
			}
			// Cache expired, remove it
			delete(bv.cache, cacheKey)
		}
		uncachedCandidates = append(uncachedCandidates, candidate)
	}
	bv.cacheMu.RUnlock()
	
	log.Printf("📊 Cache stats: %d cached, %d need validation", len(cachedResults), len(uncachedCandidates))
	
	// Validate uncached candidates in parallel
	newResults := make([]ValidationResult, len(uncachedCandidates))
	var wg sync.WaitGroup
	
	for i, candidate := range uncachedCandidates {
		wg.Add(1)
		go func(index int, cand KeyCandidateEnhanced) {
			defer wg.Done()
			
			// Acquire rate limit token
			select {
			case bv.awsRateLimit <- struct{}{}:
				defer func() { <-bv.awsRateLimit }() // Release token
			case <-ctx.Done():
				newResults[index] = ValidationResult{
					Candidate: cand,
					IsValid:   false,
					Error:     ctx.Err(),
				}
				return
			}
			
			// Validate the key
			result := bv.validateSingleKey(ctx, cand)
			newResults[index] = result
			
			// Cache the result
			bv.cacheResult(cand, result)
			
		}(i, candidate)
	}
	
	// Wait for all validations to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// All validations completed
	case <-ctx.Done():
		log.Printf("⚠️  Batch validation cancelled")
		return nil, ctx.Err()
	}
	
	// Combine cached and new results
	allResults := append(cachedResults, newResults...)
	
	// Convert valid results to findings
	var findings []AWSKeyFinding
	validCount := 0
	
	for _, result := range allResults {
		if result.IsValid {
			validCount++
			finding := bv.convertToFinding(result)
			findings = append(findings, finding)
		}
	}
	
	log.Printf("✅ Batch validation complete: %d/%d valid keys found", validCount, len(candidates))
	return findings, nil
}

// validateSingleKey validates a single AWS key candidate
func (bv *BatchValidator) validateSingleKey(ctx context.Context, candidate KeyCandidateEnhanced) ValidationResult {
	result := ValidationResult{
		Candidate: candidate,
		IsValid:   false,
	}
	
	// Create AWS config with timeout
	validationCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	
	cfg, err := config.LoadDefaultConfig(validationCtx,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			candidate.AccessKey, candidate.SecretKey, "")),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		result.Error = err
		return result
	}
	
	// Test with STS GetCallerIdentity
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(validationCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		result.Error = err
		return result
	}
	
	// Key is valid, extract account information
	result.IsValid = true
	result.AccountInfo = AWSAccountInfo{}
	
	if callerIdentity.Account != nil {
		result.AccountInfo.AccountID = *callerIdentity.Account
	}
	if callerIdentity.Arn != nil {
		result.AccountInfo.ARN = *callerIdentity.Arn
		// Extract username from ARN
		if userStart := findSubstring(result.AccountInfo.ARN, "user/"); userStart != -1 {
			result.AccountInfo.UserName = result.AccountInfo.ARN[userStart+5:]
		}
	}
	
	// Check permissions in parallel (non-blocking)
	go func() {
		permissions := bv.checkPermissions(validationCtx, cfg, result.AccountInfo.UserName)
		
		// Update the cached result with permissions
		bv.cacheMu.Lock()
		cacheKey := candidate.AccessKey + ":" + candidate.SecretKey
		if cached, exists := bv.cache[cacheKey]; exists {
			cached.Result.AccountInfo.Permissions = permissions
		}
		bv.cacheMu.Unlock()
	}()
	
	return result
}

// checkPermissions tests various AWS permissions for the key
func (bv *BatchValidator) checkPermissions(ctx context.Context, cfg aws.Config, userName string) []string {
	var permissions []string
	
	// Test IAM permissions
	iamClient := iam.NewFromConfig(cfg)
	
	// Try to list users
	maxItems := int32(1)
	if _, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{MaxItems: &maxItems}); err == nil {
		permissions = append(permissions, "iam:ListUsers")
	}
	
	// Try to get user info
	if userName != "" {
		if _, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: &userName}); err == nil {
			permissions = append(permissions, "iam:GetUser")
		}
	}
	
	// Test S3 permissions
	s3Client := s3.NewFromConfig(cfg)
	if _, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil {
		permissions = append(permissions, "s3:ListBuckets")
	}
	
	return permissions
}

// cacheResult stores a validation result in the cache
func (bv *BatchValidator) cacheResult(candidate KeyCandidateEnhanced, result ValidationResult) {
	cacheKey := candidate.AccessKey + ":" + candidate.SecretKey
	
	bv.cacheMu.Lock()
	defer bv.cacheMu.Unlock()
	
	bv.cache[cacheKey] = &CachedValidation{
		Result:    result,
		Timestamp: time.Now(),
	}
}

// convertToFinding converts a validation result to an AWSKeyFinding
func (bv *BatchValidator) convertToFinding(result ValidationResult) AWSKeyFinding {
	now := time.Now()
	
	finding := AWSKeyFinding{
		AccessKey:    result.Candidate.AccessKey,
		SecretKey:    result.Candidate.SecretKey,
		Repository:   result.Candidate.File.Repository.GetFullName(),
		FileURL:      result.Candidate.File.GetHTMLURL(),
		FilePath:     result.Candidate.File.GetPath(),
		DiscoveredAt: now,
		ValidatedAt:  now,
		AccountID:    result.AccountInfo.AccountID,
		UserName:     result.AccountInfo.UserName,
		ARN:          result.AccountInfo.ARN,
		Permissions:  result.AccountInfo.Permissions,
		CommitSHA:    result.Candidate.File.GetSHA(),
	}
	
	return finding
}

// CleanCache removes expired entries from the validation cache
func (bv *BatchValidator) CleanCache() {
	bv.cacheMu.Lock()
	defer bv.cacheMu.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for key, cached := range bv.cache {
		if now.Sub(cached.Timestamp) > bv.cacheTimeout {
			delete(bv.cache, key)
			expiredCount++
		}
	}
	
	if expiredCount > 0 {
		log.Printf("🧹 Cleaned %d expired cache entries", expiredCount)
	}
}

// GetCacheStats returns statistics about the validation cache
func (bv *BatchValidator) GetCacheStats() (total int, expired int) {
	bv.cacheMu.RLock()
	defer bv.cacheMu.RUnlock()
	
	now := time.Now()
	total = len(bv.cache)
	
	for _, cached := range bv.cache {
		if now.Sub(cached.Timestamp) > bv.cacheTimeout {
			expired++
		}
	}
	
	return total, expired
}

// Helper function to find substring (Go doesn't have strings.Index in this context)
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}