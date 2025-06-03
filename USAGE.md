# AWS Key Hunter - Usage Guide

## Overview
AWS Key Hunter is a tool that continuously scans GitHub for exposed AWS access keys and validates them.

## Features
- 🔍 Searches GitHub for AWS access keys (starting with "AKIA")
- ✅ Validates keys using AWS STS GetCallerIdentity
- 💾 Saves valid keys with full details (account ID, username, ARN)
- 🔄 Tracks processed repositories to avoid duplicates
- 📊 Provides validation reports and permission checking

## Setup
1. Create a `.env` file with:
   ```
   GITHUB_TOKEN=your_github_token_here
   DISCORD_WEBHOOK=your_discord_webhook_url_here (optional)
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

## Running the Scanner
```bash
go run cmd/awsKeyhunter.go
```

The scanner will:
- Search GitHub every minute using different search strategies
- Validate found keys in real-time
- Save valid keys to `aws_keys_found.json` and `aws_keys_found.json.csv`
- Track processed files in `processed_repos.json`

## Viewing Found Keys
```bash
go run cmd/viewKeys.go
```

Shows:
- All discovered keys with details
- Repository information
- Discovery timestamps
- Summary statistics

## Validating Keys
```bash
# Validate only new keys (skips previously validated)
go run cmd/validateKeys.go

# Force revalidation of all keys
go run cmd/validateKeys.go --force
```

The validator:
- Tests if keys are still active
- Checks IAM and S3 permissions
- Saves results to `validation_results.json`
- Creates a readable report in `validation_report.txt`

## Output Files
- `aws_keys_found.json` - All discovered valid keys
- `aws_keys_found.json.csv` - CSV format for spreadsheets
- `processed_repos.json` - Tracking file to avoid reprocessing
- `validation_results.json` - Detailed validation results
- `validation_report.txt` - Human-readable validation report

## Search Strategies
The tool rotates between multiple search strategies:
1. Recently indexed files with AWS keys
2. Recently updated configuration files
3. Language-specific files (Python, JavaScript, Java)
4. Docker and CI/CD configuration files

## Notes
- The tool respects GitHub API rate limits
- Processes are cleaned up after 7 days by default
- Only public repositories are scanned
- Keys are validated before being saved