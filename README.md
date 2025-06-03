# AWS-Key-Hunter

AWS Key Hunter is a production-ready tool that continuously scans GitHub repositories for exposed AWS access keys, validates them in real-time, and provides comprehensive reporting with permission analysis.

## Features 🚀

- **Intelligent Scanning**: Contextual AWS key extraction with confidence scoring to reduce false positives
- **Rate Limiting**: Built-in GitHub API rate limiting with exponential backoff and smart retry logic
- **Real-time Validation**: Validates discovered keys using AWS STS and checks IAM/S3 permissions
- **Key Storage**: Saves valid keys with full metadata (account ID, username, ARN, permissions)
- **Deduplication**: Repository tracking prevents redundant processing and API waste
- **Robust Architecture**: Goroutine supervisor with health checks and automatic restart capability
- **Multiple Formats**: Export findings to JSON and CSV formats
- **Advanced Deduplication**: Account-level grouping, repository relationship detection, and content similarity analysis
- **Progress Monitoring**: Real-time progress indicators and comprehensive logging
- **Graceful Shutdown**: Clean context-based shutdown handling
- **Discord Integration**: Optional Discord alerts for valid findings 

## Installation 📥

### Prerequisites
- Go 1.19 or later
- Valid GitHub Personal Access Token with appropriate scopes
- (Optional) Discord webhook URL for alerts

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/frankea/AWS-Key-Hunter.git
   cd AWS-Key-Hunter
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Create a `.env` file:
   ```env
   GITHUB_TOKEN=your_github_personal_access_token
   DISCORD_WEBHOOK=your_discord_webhook_url_here (optional)
   ```

### Using Docker

Build the Docker image:
```bash
docker build -t aws-key-hunter .
```

Run the container:
```bash
docker run --rm -d --name aws-key-hunter --env-file .env aws-key-hunter
```

## Usage 🛠

### Main Scanner
Start the continuous GitHub scanner:
```bash
go run cmd/awskeyhunter/main.go
```

### View Found Keys
Display all discovered keys with details:
```bash
go run cmd/viewkeys/main.go
```

### Deduplication Analysis
View duplicate detection statistics and account groupings:
```bash
go run cmd/dedup-stats/main.go
```

### Building Binaries
```bash
# Build the main scanner
go build -o awsKeyHunter cmd/awskeyhunter/main.go

# Build the key viewer
go build -o viewKeys cmd/viewkeys/main.go

# Run the scanner
./awsKeyHunter
```

## Disclaimer ⚠️

This tool was created for educational and experimental purposes only. They are not intended to be used for malicious activities or to harm others in any way. I do not endorse or encourage the use of this tool or information for illegal, unethical, or harmful actions.

By using this tool, you agree to accept full responsibility for any consequences that may arise from its use. I will not be held accountable for any damages, losses, or legal repercussions resulting from the misuse of this tool or the information provided.

Use at your own risk.

## Contributing 🤝

Contributions are welcome! Feel free to open an issue or submit a PR.