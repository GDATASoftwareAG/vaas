package main

import (
	"GDATACyberDefense/cleanup-packages/internal/cleanup"
	"context"
	"fmt"
	"github.com/docker/docker/client"
	"github.com/gofri/go-github-ratelimit/v2/github_ratelimit"
	"github.com/google/go-github/v69/github"
	"os"
)

func main() {
	rateLimiter := github_ratelimit.NewClient(nil)
	authToken := os.Getenv("PAT_CONTAINER_REGISTRY")
	registryUsername := "GdataGithubBot"

	githubClient := github.NewClient(rateLimiter).WithAuthToken(authToken)
	docker, _ := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	ctx := context.Background()

	dryRun := false

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--dry-run":
			dryRun = true
		default:
			panic(fmt.Sprintf("unknown flag: %s", os.Args[0]))
		}
	}
	cleanup.NewCleanup(githubClient, docker, authToken, registryUsername).Run(ctx, dryRun)
}
