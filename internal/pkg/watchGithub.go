package pkg

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

var (
	repoTracker *RepositoryTracker
)

func init() {
	var err error
	repoTracker, err = NewRepositoryTracker("processed_repos.json")
	if err != nil {
		log.Printf("Warning: Could not initialize repository tracker: %v", err)
	}
}

func SearchGithub(githubToken string) {
	ctx := context.Background()

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubToken})
	client := github.NewClient(oauth2.NewClient(ctx, ts))

	// Clean old entries (older than 7 days)
	if repoTracker != nil {
		if err := repoTracker.CleanOldEntries(7 * 24 * time.Hour); err != nil {
			log.Printf("Error cleaning old entries: %v", err)
		}
	}

	// Use multiple search strategies to find different results
	searchStrategies := []struct {
		query string
		sort  string
		desc  string
	}{
		// Search for recently indexed files
		{
			query: buildDateRangeQuery("AKIA", time.Now().Add(-24*time.Hour)),
			sort:  "indexed",
			desc:  "Recently indexed files",
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
	}

	for _, strategy := range searchStrategies {
		log.Printf("🔍 Searching GitHub with strategy: %s", strategy.desc)
		searchWithPagination(ctx, client, strategy.query, strategy.sort)
	}
}

func buildDateRangeQuery(baseQuery string, since time.Time) string {
	// GitHub supports created: and pushed: qualifiers
	dateStr := since.Format("2006-01-02")
	return fmt.Sprintf("%s created:>%s OR %s pushed:>%s filename:.env OR filename:.ini OR filename:.yml OR filename:.yaml OR filename:.json",
		baseQuery, dateStr, baseQuery, dateStr)
}

func searchWithPagination(ctx context.Context, client *github.Client, query, sortBy string) {
	opt := &github.SearchOptions{
		Sort:  sortBy,
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100, // Maximum allowed by GitHub
			Page:    1,
		},
	}

	processedInThisRun := 0
	maxPages := 5 // Limit pages to avoid rate limiting

	for page := 1; page <= maxPages; page++ {
		opt.Page = page

		results, resp, err := client.Search.Code(ctx, query, opt)
		if err != nil {
			log.Printf("Error searching GitHub (page %d): %v", page, err)

			// Check for rate limit
			if _, ok := err.(*github.RateLimitError); ok {
				log.Println("Rate limit hit, waiting before retry...")
				time.Sleep(1 * time.Minute)
			}
			break
		}

		log.Printf("📄 Processing page %d/%d (found %d results)", page, maxPages, len(results.CodeResults))

		for _, file := range results.CodeResults {
			// Skip if already processed recently
			if repoTracker != nil {
				repoFullName := file.Repository.GetFullName()
				filePath := file.GetPath()

				if repoTracker.IsProcessed(repoFullName, filePath) {
					log.Printf("⏭️  Skipping already processed: %s/%s", repoFullName, filePath)
					continue
				}
			}

			checkFileContent(ctx, client, &file)
			processedInThisRun++

			// Mark as processed
			if repoTracker != nil {
				if err := repoTracker.MarkProcessed(file.Repository.GetFullName(), file.GetPath()); err != nil {
					log.Printf("Error marking file as processed: %v", err)
				}
			}

			// Add a small delay to avoid hitting rate limits
			time.Sleep(100 * time.Millisecond)
		}

		// Check if there are more pages
		if resp.LastPage == 0 || page >= resp.LastPage {
			break
		}

		// Delay between pages to avoid rate limiting
		time.Sleep(2 * time.Second)
	}

	log.Printf("✅ Processed %d new files in this search", processedInThisRun)
}
