package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iamlucif3r/aws-key-hunter/internal/pkg"
	"github.com/joho/godotenv"
)

const (
	Red    = "\033[31m"
	Yellow = "033[33m"
	Green  = "033[32m"
	Reset  = "\033[0m"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}
func main() {
	fmt.Println(Red + "┏┓┓ ┏┏┓  ┓┏┓      ┓┏     		" + Reset)
	fmt.Println(Red + "┣┫┃┃┃┗┓━━┃┫ ┏┓┓┏━━┣┫┓┏┏┓╋┏┓┏┓	" + Reset)
	fmt.Println(Red + "┛┗┗┻┛┗┛  ┛┗┛┗ ┗┫  ┛┗┗┻┛┗┗┗ ┛ 	" + Reset)
	fmt.Println(Red + "               ┛   v1.0.0      	" + Reset)
	fmt.Println()
	log.Println(Yellow + "🚀 Starting AWS Key Scanner..." + Reset)

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Fatal("GITHUB_TOKEN is not set")
	}

	// Create supervisor for managing goroutines
	supervisor := pkg.NewSupervisor()
	
	// Add file watcher worker (this already includes GitHub searching)
	supervisor.AddWorker("file-watcher", func(ctx context.Context) error {
		return pkg.WatchNewFilesWithContext(ctx, githubToken)
	}, time.Minute, 5) // Restart after 1 minute, max 5 restarts
	
	// Start supervisor
	supervisor.Start()
	
	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Block until signal received
	sig := <-sigChan
	log.Printf("\n🛑 Received signal: %v", sig)
	log.Println("🛑 Shutting down gracefully...")
	
	// Stop the supervisor
	supervisor.Stop()
	
	// Exit cleanly
	log.Println("👋 Goodbye!")
	os.Exit(0)
}
