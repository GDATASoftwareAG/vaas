package main

import (
	"GDATACyberDefense/cleanup-packages/internal/cleanup"
	"fmt"

	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v58/github"
)

func main() {
	rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	client := github.NewClient(rateLimiter).WithAuthToken("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")

	cleanup.Cleanup(client)
}
