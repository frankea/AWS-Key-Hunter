# AWS Key Hunter - Usage Guide

## Overview
AWS Key Hunter is a production-ready tool that continuously scans GitHub for exposed AWS access keys, validates them in real-time, and provides comprehensive security analysis.

## Key Features
- 🔍 **Contextual Key Detection**: Advanced pattern matching with confidence scoring
- ⚡ **Rate Limiting**: Intelligent GitHub API usage with exponential backoff
- ✅ **Real-time Validation**: Immediate AWS STS validation with permission analysis
- 💾 **Comprehensive Storage**: Full metadata including account details and permissions
- 🔄 **Smart Deduplication**: Repository tracking prevents redundant processing
- 🛡️ **Robust Architecture**: Supervised goroutines with health checks and auto-restart
- 📊 **Multiple Export Formats**: JSON and CSV output for analysis
- 🚨 **Discord Integration**: Optional real-time alerts for valid findings

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
- Search GitHub every 2 minutes using rotating search strategies
- Apply contextual key extraction with confidence scoring
- Validate found keys in real-time using AWS STS
- Check IAM and S3 permissions for valid keys
- Save valid keys to `aws_keys_found.json` and `aws_keys_found.json.csv`
- Track processed files in `processed_repos.json` to avoid duplicates
- Respect GitHub API rate limits with intelligent backoff
- Provide real-time progress indicators and status updates

## Viewing Found Keys
```bash
go run cmd/viewKeys.go
```

Shows:
- All discovered keys with full details
- Repository information and file paths
- Discovery and validation timestamps
- Account details (Account ID, Username, ARN)
- Permission analysis (IAM and S3 capabilities)
- Summary statistics

## Key Validation Process
The tool automatically validates keys during discovery:
- Tests if keys are active using AWS STS GetCallerIdentity
- Extracts account information (Account ID, Username, ARN)
- Checks IAM permissions (ListUsers, GetUser)
- Tests S3 permissions (ListBuckets)
- Saves comprehensive results with permission details

## Output Files
- `aws_keys_found.json` - All discovered valid keys with full metadata
- `aws_keys_found.json.csv` - CSV format for spreadsheet analysis
- `processed_repos.json` - Repository tracking to prevent reprocessing

## Search Strategies
The tool intelligently rotates between 7 search strategies to maximize coverage:
1. **Recently Indexed Files**: Files indexed in the last 24 hours with AWS keys
2. **Recently Updated Files**: Configuration files sorted by last update
3. **Language-Specific Search**: Python, JavaScript, Java files containing keys
4. **Small Config Files**: Configuration files under 10KB (often more recent)
5. **Properties Files**: .properties, .cfg, and credential files
6. **Docker/CI Files**: Dockerfiles and CI/CD configuration files
7. **Secret Paths**: Files in config/, settings/, .aws/ directories

## Rate Limiting & Performance
- **Smart API Usage**: Uses only 2 strategies per cycle (reduced from 7) to avoid rate limits
- **Conservative Limits**: 4000 requests/hour (buffer below GitHub's 5000 limit)
- **Exponential Backoff**: Automatic retry with increasing delays on rate limit hits
- **Progress Indicators**: Real-time feedback during long operations
- **Graceful Shutdown**: Clean context handling for interruption

## Architecture Features
- **Goroutine Supervision**: Health checks and automatic restart of failed workers
- **Context-Aware Cancellation**: Clean shutdown across all components
- **Confidence Scoring**: Contextual key extraction reduces false positives
- **Memory Efficient**: Streaming processing with minimal memory footprint

## Notes
- Only public repositories are scanned
- Keys are validated in real-time before storage
- All API rate limits are automatically respected
- Tool provides comprehensive logging for monitoring and debugging