// Package pkg provides GitHub monitoring and AWS key detection functionality
package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

const (
	// Search cycle timing
	searchCycleInterval     = 2 * time.Minute
	searchCountdownInterval = 10 * time.Second

	// Timeouts
	awsValidationTimeout = 10 * time.Second

	// Page processing limits
	maxFilesPerPage   = 100
	delayBetweenFiles = 50 * time.Millisecond
	delayBetweenPages = 1 * time.Second
)

var (
	keyStorage   *KeyStorage
	rateLimiter  *RateLimiter
	keyExtractor *ContextualKeyExtractor
)

func init() {
	var err error
	keyStorage, err = NewKeyStorage("aws_keys_found.json")
	if err != nil {
		log.Printf("Warning: Could not initialize key storage: %v", err)
	}

	// Initialize rate limiter with conservative limit
	const defaultRateLimit = 4000 // Leave buffer for 5000/hour limit
	rateLimiter = NewRateLimiter(defaultRateLimit)

	// Initialize contextual key extractor
	keyExtractor = NewContextualKeyExtractor()
}

func WatchNewFiles(githubToken string) {
	ctx := context.Background()
	WatchNewFilesWithContext(ctx, githubToken)
}

func WatchNewFilesWithContext(ctx context.Context, githubToken string) error {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubToken})
	client := github.NewClient(oauth2.NewClient(ctx, ts))

	// Initialize tracker if not already done
	if repoTracker == nil {
		var err error
		repoTracker, err = NewRepositoryTracker("processed_repos.json")
		if err != nil {
			log.Printf("Warning: Could not initialize repository tracker: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Stopping file watcher")
			return ctx.Err()
		default:
		}

		log.Println("🔍 Starting GitHub search cycle...")

		// Use multiple search strategies (borrowed from github-search worker)
		searchStrategies := []struct {
			query string
			sort  string
			desc  string
		}{
			// Search for recently indexed files
			{
				query: fmt.Sprintf("AKIA created:>%s filename:.env OR filename:.ini OR filename:.yml OR filename:.yaml OR filename:.json",
					time.Now().Add(-24*time.Hour).Format("2006-01-02T15:04:05Z")),
				sort: "indexed",
				desc: "Recently indexed files",
			},
			// Search for recently updated files
			{
				query: "AKIA filename:.env OR filename:.ini OR filename:.yml OR filename:.yaml OR filename:.json",
				sort:  "updated",
				desc:  "Recently updated files",
			},
			// Search for files in specific languages (often overlooked)
			{
				query: "AKIA language:python OR language:javascript OR language:java",
				sort:  "indexed",
				desc:  "Language-specific files",
			},
			// Search for config files with size constraints (often more recent)
			{
				query: "AKIA filename:config OR filename:settings size:<10000",
				sort:  "indexed",
				desc:  "Small config files",
			},
			// Search for AWS keys in different file types
			{
				query: "AKIA filename:.properties OR filename:.cfg OR filename:credentials",
				sort:  "indexed",
				desc:  "Configuration files",
			},
			// Search for keys in docker and CI/CD files
			{
				query: "AKIA filename:Dockerfile OR filename:.gitlab-ci.yml OR filename:.github",
				sort:  "indexed",
				desc:  "Docker and CI/CD files",
			},
			// Search in specific paths that often contain secrets
			{
				query: "AKIA path:config OR path:settings OR path:.aws",
				sort:  "indexed",
				desc:  "Secret paths",
			},
		}

		totalProcessed := 0
		totalSkipped := 0

		// Rotate through strategies to avoid hitting rate limits too quickly
		// Use only 2 strategies per cycle instead of all 7
		strategyOffset := time.Now().Unix() % int64(len(searchStrategies))
		selectedStrategies := []struct {
			query string
			sort  string
			desc  string
		}{
			searchStrategies[strategyOffset],
			searchStrategies[(strategyOffset+1)%int64(len(searchStrategies))],
		}

		for _, strategy := range selectedStrategies {
			// Check for cancellation before starting each strategy
			select {
			case <-ctx.Done():
				log.Printf("⚠️  Stopping search cycle due to cancellation")
				return ctx.Err()
			default:
			}

			log.Printf("🔍 Searching with strategy: %s", strategy.desc)
			processed, skipped := searchWithStrategy(ctx, client, strategy.query, strategy.sort)
			totalProcessed += processed
			totalSkipped += skipped
		}

		log.Printf("✅ Cycle complete: %d new files processed, %d already seen", totalProcessed, totalSkipped)

		// Wait before next search cycle with countdown
		log.Printf("⏳ Waiting %v before next search cycle...", searchCycleInterval)
		remainingTime := searchCycleInterval
		for remainingTime > 0 {
			if remainingTime%30*time.Second == 0 || remainingTime <= searchCountdownInterval {
				log.Printf("⏱️  Next search in %v...", remainingTime.Round(time.Second))
			}
			sleepTime := searchCountdownInterval
			if remainingTime < sleepTime {
				sleepTime = remainingTime
			}
			time.Sleep(sleepTime)
			remainingTime -= sleepTime
			// Check for cancellation during wait
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
	}
}

func searchWithStrategy(ctx context.Context, client *github.Client, query, sortBy string) (int, int) {
	opt := &github.SearchOptions{
		Sort:  sortBy,
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: maxFilesPerPage, // Maximum allowed by GitHub
			Page:    1,
		},
	}

	processedCount := 0
	skippedCount := 0
	const maxPagesPerSearch = 3 // Reduced to avoid rate limiting
	maxPages := maxPagesPerSearch

	for page := 1; page <= maxPages; page++ {
		// Check for cancellation before starting each page
		select {
		case <-ctx.Done():
			log.Printf("⚠️  Stopping search due to cancellation")
			return processedCount, skippedCount
		default:
		}

		opt.Page = page

		// Wait if rate limited
		if err := rateLimiter.WaitIfNeeded(); err != nil {
			log.Printf("Rate limit wait error: %v", err)
			break
		}

		var results *github.CodeSearchResult
		var resp *github.Response

		// Retry with backoff
		err := RetryWithBackoff(ctx, 3, func() error {
			var searchErr error
			results, resp, searchErr = client.Search.Code(ctx, query, opt)
			if searchErr != nil {
				rateLimiter.HandleError(searchErr)
				return searchErr
			}
			return nil
		})

		if err != nil {
			log.Printf("Error searching GitHub (page %d): %v", page, err)
			break
		}

		// Check rate limit from response
		rateLimiter.CheckRateLimit(resp)
		rateLimiter.ResetBackoff() // Reset backoff after success

		log.Printf("📄 Processing page %d/%d (found %d results)", page, maxPages, len(results.CodeResults))

		for i, file := range results.CodeResults {
			// Check for cancellation at the start of each file processing
			select {
			case <-ctx.Done():
				log.Printf("⚠️  Stopping file processing due to cancellation")
				return processedCount, skippedCount
			default:
			}

			// Skip if already processed
			if repoTracker != nil {
				repoFullName := file.Repository.GetFullName()
				filePath := file.GetPath()

				if repoTracker.IsProcessed(repoFullName, filePath) {
					skippedCount++
					continue
				}
			}

			// Show progress every 10 files to avoid spam but provide feedback
			if i%10 == 0 || len(results.CodeResults) < 20 {
				log.Printf("   [%d/%d] 🔍 Processing: %s", i+1, len(results.CodeResults), file.GetPath())
			}

			checkFileContent(ctx, client, &file)
			processedCount++

			// Mark as processed
			if repoTracker != nil {
				if err := repoTracker.MarkProcessed(file.Repository.GetFullName(), file.GetPath()); err != nil {
					log.Printf("Error marking file as processed: %v", err)
				}
			}

			// Add a small delay to avoid hitting rate limits
			time.Sleep(delayBetweenFiles)
		}

		// Check if there are more pages
		if resp.LastPage == 0 || page >= resp.LastPage {
			break
		}

		// Delay between pages to avoid rate limiting
		time.Sleep(delayBetweenPages)
	}

	return processedCount, skippedCount
}

func checkFileContent(ctx context.Context, client *github.Client, file *github.CodeResult) {
	content, err := fetchFileContent(ctx, client, file)
	if err != nil {
		// Don't log errors if context was canceled (during shutdown)
		if ctx.Err() == nil {
			log.Printf("❌ Error fetching file content: %v", err)
		}
		return
	}

	// Fetch commit information
	commitDate, commitAuthor := fetchCommitInfo(ctx, client, file)

	awsKeyPairs := extractAWSKeys(content)

	for _, creds := range awsKeyPairs {
		accessKey := creds["access_key"]
		secretKey := creds["secret_key"]

		accountInfo, isValid := validateAWSKeys(accessKey, secretKey)
		if isValid {
			log.Printf("🚨 Valid AWS Key Found! Repo: %s | File: %s", file.Repository.GetFullName(), file.GetHTMLURL())

			// Save to file
			if keyStorage != nil {
				finding := AWSKeyFinding{
					AccessKey:    accessKey,
					SecretKey:    secretKey,
					Repository:   file.Repository.GetFullName(),
					FileURL:      file.GetHTMLURL(),
					FilePath:     file.GetPath(),
					ValidatedAt:  time.Now(),
					AccountID:    accountInfo.AccountID,
					UserName:     accountInfo.UserName,
					ARN:          accountInfo.ARN,
					Permissions:  accountInfo.Permissions,
					CommitSHA:    file.GetSHA(),
					CommitDate:   commitDate,
					CommitAuthor: commitAuthor,
				}
				if err := keyStorage.AddFinding(finding); err != nil {
					log.Printf("Error saving key finding: %v", err)
				} else {
					log.Printf("💾 Key finding saved to aws_keys_found.json")
				}
			}

			sendDiscordAlert(file.Repository.GetFullName(), file.GetHTMLURL(), []string{accessKey})
		}
	}
}

type AWSAccountInfo struct {
	AccountID   string
	UserName    string
	ARN         string
	Permissions []string
}

func validateAWSKeys(accessKey, secretKey string) (AWSAccountInfo, bool) {
	accountInfo := AWSAccountInfo{}

	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), awsValidationTimeout)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		log.Printf("❌ Failed to load AWS config for key %s: %v", accessKey, err)
		return accountInfo, false
	}

	stsClient := sts.NewFromConfig(cfg)

	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// Extract just the meaningful error part
		errMsg := err.Error()
		if strings.Contains(errMsg, "InvalidClientTokenId") {
			log.Printf("❌ Invalid AWS Key: %s (Invalid token)", accessKey)
		} else if strings.Contains(errMsg, "SignatureDoesNotMatch") {
			log.Printf("❌ Invalid AWS Key: %s (Wrong signature)", accessKey)
		} else if strings.Contains(errMsg, "TokenRefreshRequired") {
			log.Printf("❌ Invalid AWS Key: %s (Token expired)", accessKey)
		} else if strings.Contains(errMsg, "AccessDenied") {
			log.Printf("❌ Invalid AWS Key: %s (Access denied)", accessKey)
		} else {
			log.Printf("❌ Invalid AWS Key: %s (Auth failed)", accessKey)
		}
		return accountInfo, false
	}

	// Extract account information
	if callerIdentity.Account != nil {
		accountInfo.AccountID = *callerIdentity.Account
	}
	if callerIdentity.Arn != nil {
		accountInfo.ARN = *callerIdentity.Arn
		// Extract username from ARN if possible
		if strings.Contains(accountInfo.ARN, "user/") {
			parts := strings.Split(accountInfo.ARN, "user/")
			if len(parts) > 1 {
				accountInfo.UserName = parts[1]
			}
		}
	}

	// Check permissions
	permissions := checkPermissions(ctx, cfg, accountInfo.UserName)
	accountInfo.Permissions = permissions

	if len(permissions) > 0 {
		log.Printf("✅ Valid AWS Key Found: %s (Account: %s, User: %s, Permissions: %v)",
			accessKey, accountInfo.AccountID, accountInfo.UserName, permissions)
	} else {
		log.Printf("✅ Valid AWS Key Found: %s (Account: %s, User: %s, Limited permissions)",
			accessKey, accountInfo.AccountID, accountInfo.UserName)
	}
	return accountInfo, true
}

func checkPermissions(ctx context.Context, cfg aws.Config, userName string) []string {
	permissions := []string{}

	// Test IAM permissions
	iamClient := iam.NewFromConfig(cfg)

	// Try to list users (requires iam:ListUsers)
	maxItems := int32(1)
	_, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{MaxItems: &maxItems})
	if err == nil {
		permissions = append(permissions, "iam:ListUsers")
	}

	// Try to get user (requires iam:GetUser)
	if userName != "" {
		_, err = iamClient.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
		if err == nil {
			permissions = append(permissions, "iam:GetUser")
		}
	}

	// Test S3 permissions
	s3Client := s3.NewFromConfig(cfg)

	// Try to list buckets (requires s3:ListBuckets)
	_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err == nil {
		permissions = append(permissions, "s3:ListBuckets")
	}
	return permissions
}

func fetchFileContent(ctx context.Context, client *github.Client, file *github.CodeResult) (string, error) {
	repo := file.GetRepository()
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	filePath := file.GetPath()

	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, filePath, nil)
	if err != nil {
		return "", fmt.Errorf("GitHub API error fetching file content: %v", err)
	}

	if fileContent == nil {
		return "", errors.New("file content is nil")
	}

	encoding := fileContent.GetEncoding()

	contentStr, err := fileContent.GetContent()
	if err != nil {
		return "", fmt.Errorf("error retrieving file content: %v", err)
	}

	contentStr = strings.TrimSpace(contentStr)

	if encoding == "" || encoding == "none" {
		log.Printf("ℹ️ Info: Plain text detected in %s/%s/%s", owner, repoName, filePath)
		return contentStr, nil
	}

	if encoding == "base64" {

		decodedContent, err := base64.StdEncoding.DecodeString(contentStr)
		if err != nil {
			// GitHub sometimes returns plain text with base64 encoding flag - this is normal
			return contentStr, nil
		}
		return string(decodedContent), nil
	}

	return "", fmt.Errorf("unknown encoding type: %s", encoding)
}

func extractAWSKeys(content string) []map[string]string {
	awsKeys := []map[string]string{}

	// Use contextual extraction for better accuracy
	candidates := keyExtractor.ExtractKeysWithContext(content)

	// Convert high-confidence candidates to the expected format
	for _, candidate := range candidates {
		const minConfidenceThreshold = 0.7
		if candidate.Confidence >= minConfidenceThreshold { // Only use high confidence matches
			awsKeys = append(awsKeys, map[string]string{
				"access_key": candidate.AccessKey,
				"secret_key": candidate.SecretKey,
			})
			log.Printf("🔍 Found key pair with confidence: %.2f", candidate.Confidence)
		}
	}

	return awsKeys
}

func fetchCommitInfo(ctx context.Context, client *github.Client, file *github.CodeResult) (time.Time, string) {
	var commitDate time.Time
	var commitAuthor string

	// Note: GitHub's code search API returns file SHA, not commit SHA
	// The SHA from search results is the file content SHA, which can't be used to get commit info
	// To get commit info, we would need to use the Commits API with the file path
	// This is expensive in terms of API calls, so we'll skip it for now

	// TODO: Implement proper commit fetching if needed:
	// 1. Use client.Repositories.ListCommits with path filter
	// 2. Get the most recent commit for the file
	// 3. Extract commit date and author

	return commitDate, commitAuthor
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days > 0 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}

	hours := int(d.Hours())
	if hours > 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}

	minutes := int(d.Minutes())
	if minutes > 0 {
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	return "just now"
}

func sendDiscordAlert(repo, url string, keys []string) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	message := map[string]string{
		"content": fmt.Sprintf("🚨 AWS Key Leak Detected!\nRepo: %s\nURL: %s\nKeys: %v", repo, url, keys),
	}
	jsonData, _ := json.Marshal(message)

	req, _ := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending alert to Discord: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Println("🚨 Alert sent to Discord successfully!")
}
