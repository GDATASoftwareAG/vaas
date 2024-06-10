package main

import (
	"GDATACyberDefense/cleanup-packages/internal/cleanup"
	"fmt"
	"os"

	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v62/github"
)

func main() {
	rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	client := github.NewClient(rateLimiter).WithAuthToken(os.Getenv("PAT_CONTAINER_REGISTRY"))

	cleanup.Cleanup(client)
}
