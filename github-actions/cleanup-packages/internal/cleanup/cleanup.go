package cleanup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/google/go-github/v69/github"
)

const gdataOrganisation = "GDATASoftwareAG"

var packageType = "container"
var globalNameRegex, _ = regexp.Compile(`^(gdscanserver|scanclient|vaas/.+)$`)
var globalTagsNotToDelete, _ = regexp.Compile(`^(latest|[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+|[0-9]+)(-[0-9]+)?$`)
var nowTime = time.Now()

func packageListOptions(page int, state *string) *github.PackageListOptions {
	return &github.PackageListOptions{
		ListOptions: github.ListOptions{
			Page:    page,
			PerPage: 100,
		},
		PackageType: &packageType,
		State:       state,
	}
}

// Cleanup represents a cleanup operation for packages.
type Cleanup struct {
	githubClient     *github.Client
	dockerClient     *client.Client
	authToken        string
	registryUsername string
}

// NewCleanup creates a new instance of the Cleanup struct.
// It takes in a GitHub client, a Docker client, an authentication token, and a registry username.
// It returns a Cleanup struct initialized with the provided values.
func NewCleanup(githubClient *github.Client, dockerClient *client.Client, authToken string, registryUsername string) *Cleanup {
	cleanup := Cleanup{
		githubClient:     githubClient,
		dockerClient:     dockerClient,
		authToken:        authToken,
		registryUsername: registryUsername,
	}
	return &cleanup
}

// Run executes the cleanup process for container packages.
// It retrieves the list of container packages and checks their versions.
// If a version is older than 2 months, it is deleted using the GitHub API.
// The method logs the details of the deleted versions and the total number of deleted versions for each package.
// Finally, it logs the total time taken for the deletion process.
func (cleanup *Cleanup) Run(ctx context.Context, dryRun bool) {
	start := time.Now()

	packageList := cleanup.getContainerPackages(ctx, globalNameRegex)
	var packageNames []string
	for _, pack := range packageList {
		packageNames = append(packageNames, pack.GetName())
	}
	println("Start cleanup for packages: \n\t - ", strings.Join(packageNames, "\n\t - "))

	for idx, pack := range packageList {
		println(fmt.Sprintf("(%.2d|%.02d) Start cleanup for %s", idx+1, len(packageList), pack.GetName()))
		println("cleanup tagged packages for ", pack.GetName())
		taggedVersionsToDelete, err := cleanup.collectTaggedVersionsToDelete(ctx, pack.GetName())
		if err != nil {
			log.Printf("error getting tagged versions to delete for %s: %s\n", pack.GetName(), err)
			continue
		}

		for _, version := range taggedVersionsToDelete {
			cleanup.deleteVersion(ctx, version, pack.GetName(), dryRun)
		}

		println("cleanup untagged packages for ", pack.GetName())
		versionsChan := cleanup.collectUntaggedVersionsToDelete(ctx, pack.GetName())
		deleted := 0
		for version := range versionsChan {
			deleted++
			cleanup.deleteVersion(ctx, version, pack.GetName(), dryRun)
		}
		if deleted == 0 {
			log.Println("no versions older than 2 month for package ", pack.GetName())
		} else {
			log.Printf("Deleted %d Versions for package", deleted)
		}
	}
	log.Printf("Deletion took %s", time.Since(start))
}

func (cleanup *Cleanup) deleteVersion(ctx context.Context, version *github.PackageVersion, name string, dryRun bool) {
	if len(version.Metadata.Container.Tags) > 0 {
		log.Printf(
			"deleting package %v with versions %v created %v updates %v",
			name, strings.Join(version.Metadata.Container.Tags, "|"),
			version.CreatedAt.Time, version.UpdatedAt.Time)
	} else {
		log.Printf(
			"deleting package %v with digest %v created %v updates %v",
			name, version.Name, version.CreatedAt.Time, version.UpdatedAt.Time)
	}

	if dryRun {
		return
	}

	if resp, err := cleanup.githubClient.Organizations.PackageDeleteVersion(ctx, gdataOrganisation, packageType, name, *version.ID); err != nil {
		log.Printf("error deleting version for package %s: %s\n", name, err)
		if resp != nil {
			log.Printf("\tapi response %d: %s\n", resp.StatusCode, resp.Status)
		}
	}
}

func (cleanup *Cleanup) collectTaggedVersionsToDelete(ctx context.Context, name string) ([]*github.PackageVersion, error) {
	_, packageVersionsWithTags, err := cleanup.collectPackageVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(packageVersionsWithTags, func(version *github.PackageVersion) bool {
		return !isOlderThan2Month(&nowTime, version) || !areWeAllowedToDeleteThisVersion(version)
	}), nil
}

func (cleanup *Cleanup) collectUntaggedVersionsToDelete(ctx context.Context, name string) <-chan *github.PackageVersion {
	ch := make(chan *github.PackageVersion)
	go func() {
		defer close(ch)

		packageVersionsWithoutTags, packageVersionsWithTags, err := cleanup.collectPackageVersions(ctx, name)
		if err != nil {
			log.Println(err)
			return
		}

		versionsWithTagsNotToDelete := slices.DeleteFunc(packageVersionsWithTags, func(version *github.PackageVersion) bool {
			return isOlderThan2Month(&nowTime, version) && areWeAllowedToDeleteThisVersion(version)
		})

		var dependenciesOfTaggedImages []string
		if dependenciesOfTaggedImages, err = cleanup.dockerImageDependencies(ctx, name, versionsWithTagsNotToDelete); err != nil {
			log.Println(err)
			return
		}
		for _, packVersion := range packageVersionsWithoutTags {
			if !isOlderThan2Month(&nowTime, packVersion) {
				continue
			}
			if isDependencyOfATaggedImage(packVersion, dependenciesOfTaggedImages) {
				continue
			}
			ch <- packVersion
		}
	}()
	return ch
}

func (cleanup *Cleanup) collectPackageVersions(ctx context.Context, name string) (packageVersionsWithoutTags []*github.PackageVersion, packageVersionsWithTags []*github.PackageVersion, err error) {
	nextPage := 1
	packageState := "active"
	_, lengthResponse, err := cleanup.githubClient.Organizations.PackageGetAllVersions(ctx, gdataOrganisation, packageType, name, packageListOptions(nextPage, nil))
	if err != nil {
		log.Println(lengthResponse, "\n", err)
		return
	}
	nextPage = lengthResponse.LastPage

	for {
		var packageVersionsPage []*github.PackageVersion
		var response *github.Response
		packageVersionsPage, response, err = cleanup.githubClient.Organizations.PackageGetAllVersions(ctx, gdataOrganisation, packageType, name, packageListOptions(nextPage, &packageState))
		if err != nil {
			log.Println(response, "\n", err)
			return
		}

		for i, packVersion := range packageVersionsPage {
			if len(packVersion.Metadata.Container.Tags) != 0 {
				packageVersionsWithTags = append(packageVersionsWithTags, packageVersionsPage[i])
			} else {
				packageVersionsWithoutTags = append(packageVersionsWithoutTags, packageVersionsPage[i])
			}
		}

		if response != nil {
			if response.PrevPage == 0 {
				return
			}
			nextPage = response.PrevPage
		}
	}
}

func (cleanup *Cleanup) dockerImageDependencies(ctx context.Context, packageName string, versionsWithTagsNotToDelete []*github.PackageVersion) (dependencies []string, err error) {
	pullImage := func(ctx context.Context, imageRef, authConfigEncoded string) error {
		var imagePullCloser io.ReadCloser
		if imagePullCloser, err = cleanup.dockerClient.ImagePull(context.Background(), imageRef, image.PullOptions{
			RegistryAuth: authConfigEncoded,
		}); err != nil {
			return err
		}
		defer imagePullCloser.Close()

		if _, err = io.ReadAll(imagePullCloser); err != nil {
			log.Println("Image Pull Response Error: " + err.Error())
			return err
		}
		return nil
	}

	var tags []string
	for _, version := range versionsWithTagsNotToDelete {
		tags = append(tags, version.GetName())
	}
	println("collect dependencies for package", packageName, "with tags: \n\t -", strings.Join(tags, "\n\t - "))
	for idx, version := range versionsWithTagsNotToDelete {
		println(fmt.Sprintf("(%.2d|%.2d) collect for %s", idx+1, len(versionsWithTagsNotToDelete), version.GetName()))
		imageRef := "ghcr.io/" + strings.ToLower(gdataOrganisation) + "/" + packageName + ":" + version.Metadata.Container.Tags[0]

		authConfig := registry.AuthConfig{
			Username:      cleanup.registryUsername,
			Password:      cleanup.authToken,
			ServerAddress: "https://ghcr.io/v2/",
		}
		authConfigBytes, _ := json.Marshal(authConfig)
		authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

		if err = pullImage(ctx, imageRef, authConfigEncoded); err != nil {
			return nil, err
		}

		var inspectResponse image.InspectResponse
		if inspectResponse, err = cleanup.dockerClient.ImageInspect(context.Background(), imageRef); err != nil {
			log.Println("ImageInspect: " + err.Error())
			return nil, err
		}

		var imageHistoryResponse []image.HistoryResponseItem
		if imageHistoryResponse, err = cleanup.dockerClient.ImageHistory(context.Background(), inspectResponse.ID); err != nil {
			log.Println("ImageHistory: " + err.Error())
			return nil, err
		}
		for _, layer := range imageHistoryResponse {
			dependencies = append(dependencies, layer.ID)
		}
		// remove locally
		if _, err = cleanup.dockerClient.ImageRemove(context.Background(), inspectResponse.ID, image.RemoveOptions{
			PruneChildren: true,
			Force:         true,
		}); err != nil {
			log.Println("ImageRemove error: " + err.Error())
		}
	}
	return
}

func (cleanup *Cleanup) getContainerPackages(ctx context.Context, nameRegex *regexp.Regexp) (packageList []*github.Package) {
	run := true
	nextPage := 0
	for run {
		packages, response, err := cleanup.githubClient.Organizations.ListPackages(
			ctx, gdataOrganisation, &github.PackageListOptions{
				PackageType: &packageType,
				ListOptions: github.ListOptions{
					PerPage: 100,
					Page:    nextPage,
				},
			})
		if err != nil {
			log.Println(response)
			log.Println(err)
			run = false
		}
		if response != nil {
			if response.NextPage == 0 {
				run = false
			}
			nextPage = response.NextPage
		}
		for _, pack := range packages {
			if nameRegex.Match([]byte(pack.GetName())) {
				packageList = append(packageList, pack)
			}
		}
	}
	return
}

func isDependencyOfATaggedImage(version *github.PackageVersion, versionsNotToDeleteDependencies []string) bool {
	for _, dependency := range versionsNotToDeleteDependencies {
		if dependency == *version.Name {
			return true
		}
	}
	return false
}

func areWeAllowedToDeleteThisVersion(version *github.PackageVersion) bool {
	for _, tag := range version.Metadata.Container.Tags {
		if globalTagsNotToDelete.Match([]byte(tag)) {
			return false
		}
	}
	return true
}

func isOlderThan2Month(now *time.Time, version *github.PackageVersion) bool {
	updated := version.UpdatedAt.GetTime()
	created := version.CreatedAt.GetTime()

	compareTime := updated.AddDate(0, 2, 0)
	if created.After(*updated) {
		compareTime = created.AddDate(0, 2, 0)
	}

	return compareTime.Before(*now)
}
