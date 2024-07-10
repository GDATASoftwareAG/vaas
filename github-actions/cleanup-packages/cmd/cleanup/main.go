package main

import (
	"GDATACyberDefense/cleanup-packages/internal/cleanup"
	"context"
	"fmt"
	"os"

	"github.com/docker/docker/client"
	"github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v62/github"
)

func main() {
	rateLimiter, err := github_ratelimit.NewRateLimitWaiterClient(nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	authToken := os.Getenv("PAT_CONTAINER_REGISTRY")
	registryUsername := "GdataGithubBot"

	github := github.NewClient(rateLimiter).WithAuthToken(authToken)
	docker, _ := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	context := context.Background()

	cleanup.NewCleanup(github, docker, authToken, registryUsername).Run(context)
}
