// Package pkg provides intelligent repository scoring for prioritizing AWS key searches
package pkg

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/github"
)

// RepositoryScore represents the likelihood of a repository containing AWS secrets
type RepositoryScore struct {
	Repository   string
	Language     string
	Size         int
	Stars        int
	LastActivity time.Time
	Likelihood   float64 // 0.0 to 1.0, higher = more likely to contain secrets
	Reasons      []string // Why this score was assigned
}

// RepositoryScorer evaluates repositories and files for secret likelihood
type RepositoryScorer struct {
	// Pre-compiled patterns for efficiency
	secretPatterns    []*regexp.Regexp
	configPatterns    []*regexp.Regexp
	infrastructurePatterns []*regexp.Regexp
	testPatterns      []*regexp.Regexp
	documentationPatterns []*regexp.Regexp
}

// NewRepositoryScorer creates a new repository scorer
func NewRepositoryScorer() *RepositoryScorer {
	return &RepositoryScorer{
		secretPatterns: compilePatterns([]string{
			`(?i)(secret|password|key|token|credential)`,
			`(?i)(aws|amazon|s3|ec2|lambda)`,
			`(?i)(api[_\s]*key|access[_\s]*key)`,
			`(?i)(auth|oauth|jwt)`,
		}),
		configPatterns: compilePatterns([]string{
			`\.(env|ini|conf|config|properties|yaml|yml|json)$`,
			`(?i)(config|settings|env)`,
			`(?i)(docker|terraform|ansible|kubernetes|k8s)`,
		}),
		infrastructurePatterns: compilePatterns([]string{
			`(?i)(terraform|ansible|puppet|chef|kubernetes|k8s|docker)`,
			`(?i)(infrastructure|infra|ops|devops|deploy)`,
			`(?i)(cloud|aws|azure|gcp|google)`,
		}),
		testPatterns: compilePatterns([]string{
			`(?i)(test|spec|mock|fixture|example)`,
			`\.(test|spec)\.(js|ts|py|go|java|rb)$`,
			`/tests?/`,
			`/examples?/`,
		}),
		documentationPatterns: compilePatterns([]string{
			`(?i)(doc|readme|wiki|guide|tutorial)`,
			`\.(md|txt|rst|adoc)$`,
			`/docs?/`,
		}),
	}
}

// ScoreRepository calculates the likelihood of a repository containing AWS secrets
func (rs *RepositoryScorer) ScoreRepository(repo *github.Repository) RepositoryScore {
	score := RepositoryScore{
		Repository: repo.GetFullName(),
		Language:   repo.GetLanguage(),
		Size:       repo.GetSize(),
		Stars:      repo.GetStargazersCount(),
		Likelihood: 0.5, // Start with neutral score
		Reasons:    []string{},
	}
	
	if repo.UpdatedAt != nil {
		score.LastActivity = repo.UpdatedAt.Time
	}
	
	repoName := strings.ToLower(repo.GetName())
	repoDesc := strings.ToLower(repo.GetDescription())
	language := strings.ToLower(repo.GetLanguage())
	
	// Positive indicators (increase likelihood)
	score.Likelihood += rs.evaluatePositiveIndicators(repoName, repoDesc, language, &score.Reasons)
	
	// Negative indicators (decrease likelihood)
	score.Likelihood -= rs.evaluateNegativeIndicators(repoName, repoDesc, language, &score.Reasons)
	
	// Repository characteristics
	score.Likelihood += rs.evaluateRepoCharacteristics(repo, &score.Reasons)
	
	// Normalize score to 0.0-1.0 range
	if score.Likelihood > 1.0 {
		score.Likelihood = 1.0
	} else if score.Likelihood < 0.0 {
		score.Likelihood = 0.0
	}
	
	return score
}

// ScoreFile calculates the likelihood of a specific file containing AWS secrets
func (rs *RepositoryScorer) ScoreFile(file *github.CodeResult, content string) float64 {
	baseScore := 0.5
	
	fileName := strings.ToLower(file.GetPath())
	fileContent := strings.ToLower(content)
	
	// File name/path scoring
	baseScore += rs.scoreFileName(fileName)
	
	// Content scoring
	baseScore += rs.scoreFileContent(fileContent)
	
	// File size scoring (very large files are less likely to be config files)
	if len(content) > 100000 { // 100KB
		baseScore -= 0.2
	} else if len(content) < 1000 { // Very small files might be incomplete
		baseScore -= 0.1
	}
	
	// Normalize to 0.0-1.0
	if baseScore > 1.0 {
		return 1.0
	} else if baseScore < 0.0 {
		return 0.0
	}
	
	return baseScore
}

// evaluatePositiveIndicators checks for factors that increase secret likelihood
func (rs *RepositoryScorer) evaluatePositiveIndicators(name, desc, language string, reasons *[]string) float64 {
	boost := 0.0
	
	// Language-based scoring
	switch language {
	case "javascript", "typescript", "python", "java", "go", "ruby", "php":
		boost += 0.1
		*reasons = append(*reasons, "Common backend language")
	case "shell", "dockerfile", "makefile":
		boost += 0.15
		*reasons = append(*reasons, "Infrastructure/deployment language")
	}
	
	// Repository name indicators
	for _, pattern := range rs.infrastructurePatterns {
		if pattern.MatchString(name) {
			boost += 0.2
			*reasons = append(*reasons, "Infrastructure-related name")
			break
		}
	}
	
	for _, pattern := range rs.secretPatterns {
		if pattern.MatchString(name) {
			boost += 0.15
			*reasons = append(*reasons, "Secret-related keywords in name")
			break
		}
	}
	
	// Description indicators
	for _, pattern := range rs.infrastructurePatterns {
		if pattern.MatchString(desc) {
			boost += 0.1
			*reasons = append(*reasons, "Infrastructure mentions in description")
			break
		}
	}
	
	return boost
}

// evaluateNegativeIndicators checks for factors that decrease secret likelihood
func (rs *RepositoryScorer) evaluateNegativeIndicators(name, desc, language string, reasons *[]string) float64 {
	penalty := 0.0
	
	// Documentation repositories are less likely to have real secrets
	for _, pattern := range rs.documentationPatterns {
		if pattern.MatchString(name) {
			penalty += 0.3
			*reasons = append(*reasons, "Documentation repository")
			break
		}
	}
	
	// Test/example repositories often have fake credentials
	for _, pattern := range rs.testPatterns {
		if pattern.MatchString(name) {
			penalty += 0.2
			*reasons = append(*reasons, "Test/example repository")
			break
		}
	}
	
	// Frontend-only languages are less likely to have AWS keys
	switch language {
	case "html", "css", "scss", "less":
		penalty += 0.2
		*reasons = append(*reasons, "Frontend-only language")
	}
	
	return penalty
}

// evaluateRepoCharacteristics scores based on repository metadata
func (rs *RepositoryScorer) evaluateRepoCharacteristics(repo *github.Repository, reasons *[]string) float64 {
	boost := 0.0
	
	// Recently active repositories are more likely to have current secrets
	if repo.UpdatedAt != nil {
		daysSinceUpdate := time.Since(repo.UpdatedAt.Time).Hours() / 24
		if daysSinceUpdate < 30 {
			boost += 0.1
			*reasons = append(*reasons, "Recently active")
		} else if daysSinceUpdate > 365 {
			boost -= 0.1
			*reasons = append(*reasons, "Inactive repository")
		}
	}
	
	// Very popular repositories are less likely to have real secrets (they'd be caught)
	stars := repo.GetStargazersCount()
	if stars > 1000 {
		boost -= 0.2
		*reasons = append(*reasons, "High visibility (many stars)")
	} else if stars > 100 {
		boost -= 0.1
		*reasons = append(*reasons, "Medium visibility")
	}
	
	// Forks are less likely to have unique secrets
	if repo.GetFork() {
		boost -= 0.15
		*reasons = append(*reasons, "Forked repository")
	}
	
	// Private repositories that became public might have secrets
	if !repo.GetPrivate() && repo.CreatedAt != nil {
		daysSinceCreation := time.Since(repo.CreatedAt.Time).Hours() / 24
		if daysSinceCreation > 365 {
			boost += 0.05
			*reasons = append(*reasons, "Long-running public repository")
		}
	}
	
	return boost
}

// scoreFileName evaluates filename/path for secret indicators
func (rs *RepositoryScorer) scoreFileName(fileName string) float64 {
	score := 0.0
	
	// Configuration file extensions
	for _, pattern := range rs.configPatterns {
		if pattern.MatchString(fileName) {
			score += 0.3
			break
		}
	}
	
	// Common secret file names
	secretFiles := []string{
		"credentials", "secrets", "config", "settings",
		".env", "environment", "prod", "production",
		"staging", "dev", "development", "local",
	}
	
	for _, secretFile := range secretFiles {
		if strings.Contains(fileName, secretFile) {
			score += 0.2
			break
		}
	}
	
	// Paths that commonly contain secrets
	secretPaths := []string{
		"/config/", "/configs/", "/.aws/", "/secrets/",
		"/env/", "/environments/", "/deploy/", "/deployment/",
	}
	
	for _, path := range secretPaths {
		if strings.Contains(fileName, path) {
			score += 0.25
			break
		}
	}
	
	// Reduce score for test/documentation files
	for _, pattern := range rs.testPatterns {
		if pattern.MatchString(fileName) {
			score -= 0.3
			break
		}
	}
	
	for _, pattern := range rs.documentationPatterns {
		if pattern.MatchString(fileName) {
			score -= 0.2
			break
		}
	}
	
	return score
}

// scoreFileContent evaluates file content for secret indicators
func (rs *RepositoryScorer) scoreFileContent(content string) float64 {
	score := 0.0
	
	// Count secret-related keywords
	secretKeywords := []string{
		"aws_access_key", "aws_secret", "access_key_id", "secret_access_key",
		"api_key", "api_secret", "private_key", "password", "token",
		"credential", "auth", "oauth", "jwt",
	}
	
	keywordCount := 0
	for _, keyword := range secretKeywords {
		if strings.Contains(content, keyword) {
			keywordCount++
		}
	}
	
	// More keywords = higher likelihood
	score += float64(keywordCount) * 0.1
	
	// AWS-specific indicators
	awsIndicators := []string{
		"amazon", "aws", "s3", "ec2", "lambda", "cloudformation",
		"terraform", "boto3", "aws-sdk",
	}
	
	awsCount := 0
	for _, indicator := range awsIndicators {
		if strings.Contains(content, indicator) {
			awsCount++
		}
	}
	
	score += float64(awsCount) * 0.05
	
	// Look for structured config formats
	if strings.Contains(content, "=") && strings.Contains(content, "\n") {
		score += 0.1 // Looks like key=value config
	}
	
	if strings.Contains(content, ":") && (strings.Contains(content, "{") || strings.Contains(content, "-")) {
		score += 0.1 // Looks like YAML/JSON
	}
	
	return score
}

// compilePatterns compiles a slice of regex patterns
func compilePatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		compiled[i] = regexp.MustCompile(pattern)
	}
	return compiled
}