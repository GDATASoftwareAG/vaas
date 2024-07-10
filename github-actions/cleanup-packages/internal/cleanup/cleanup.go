package cleanup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/google/go-github/v62/github"
)

const gdataOrganisation = "GDATASoftwareAG"

var packageType = "container"
var globalNameRegex, _ = regexp.Compile(`^(gdscanserver|scanclient|vaas/.+)$`)
var globalTagsNotToDelete, _ = regexp.Compile(`^(latest|[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+|[0-9]+)$`)
var nowTime = time.Now()

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
func (cleanup *Cleanup) Run(context context.Context) {
	start := time.Now()

	packageList := cleanup.getContainerPackages(context, globalNameRegex)
	for _, pack := range packageList {
		println("checking versions for package ", pack.GetName())
		versions := cleanup.getVersionsOlderThan2Month(context, pack.Name)
		deleted := 0
		for version := range versions {
			deleted++
			if len(version.Metadata.Container.Tags) > 0 {
				log.Printf(
					"deleting package %v with versions %v created %v updates %v",
					pack.GetName(), strings.Join(version.Metadata.Container.Tags, "|"),
					version.CreatedAt.Time, version.UpdatedAt.Time)
			} else {
				log.Printf(
					"deleting package %v with digest %v created %v updates %v",
					pack.GetName(), version.Name, version.CreatedAt.Time, version.UpdatedAt.Time)
			}

			cleanup.githubClient.Organizations.PackageDeleteVersion(context, gdataOrganisation, packageType, pack.GetName(), *version.ID)
		}
		if deleted == 0 {
			log.Println("no versions older than 2 month for package ", pack.GetName())
		}
		if deleted == 0 {
			log.Println("no versions older than 2 month for package ", pack.GetName())
		}
		log.Printf("Deleted %d Versions for package", deleted)
	}
	log.Printf("Deletion took %s", time.Since(start))
}

func (cleanup *Cleanup) getVersionsOlderThan2Month(context context.Context, name *string) <-chan *github.PackageVersion {
	ch := make(chan *github.PackageVersion)
	run := true
	nextPage := 1
	packageType := "container"
	packageState := "active"
	var packageVersionsWithoutTags []*github.PackageVersion
	var packageVersionsWithTags []*github.PackageVersion

	_, lengthResponse, err := cleanup.githubClient.Organizations.PackageGetAllVersions(
		context, gdataOrganisation, packageType, *name,
		&github.PackageListOptions{
			ListOptions: github.ListOptions{
				Page:    nextPage,
				PerPage: 100,
			},
			PackageType: &packageType,
		})
	if err != nil {
		log.Println(lengthResponse)
		log.Println(err)
		run = false
	}
	nextPage = lengthResponse.LastPage

	go func() {
		defer close(ch)
		for run {
			packageVersionsPage, response, err := cleanup.githubClient.Organizations.PackageGetAllVersions(
				context, gdataOrganisation, packageType, *name,
				&github.PackageListOptions{
					ListOptions: github.ListOptions{
						Page:    nextPage,
						PerPage: 100,
					},
					PackageType: &packageType,
					State:       &packageState,
				})
			if err != nil {
				log.Println(response)
				log.Println(err)
				run = false
			}
			if response != nil {
				if response.PrevPage == 0 {
					run = false
				}
				nextPage = response.PrevPage
			}
			for i, packVersion := range packageVersionsPage {
				if len(packVersion.Metadata.Container.Tags) != 0 {
					packageVersionsWithTags = append(packageVersionsWithTags, packageVersionsPage[i])
				} else {
					packageVersionsWithoutTags = append(packageVersionsWithoutTags, packageVersionsPage[i])
				}
			}
		}

		var versionsWithTagsNotToDelete []*github.PackageVersion
		for _, packVersion := range packageVersionsWithTags {
			if !isNewestDateOlderThan2Month(&nowTime, &packVersion.CreatedAt.Time, &packVersion.UpdatedAt.Time) {
				versionsWithTagsNotToDelete = append(versionsWithTagsNotToDelete, packVersion)
				continue
			}
			if !areWeAllowedToDeleteThisVersion(packVersion) {
				versionsWithTagsNotToDelete = append(versionsWithTagsNotToDelete, packVersion)
				continue
			}
			ch <- packVersion
		}

		versionsNotToDeleteDependencies, error := cleanup.getVersionsNotToDeleteDependencies(*name, versionsWithTagsNotToDelete)
		if error != nil {
			log.Println(error)
			return
		}
		for _, packVersion := range packageVersionsWithoutTags {
			if !isNewestDateOlderThan2Month(&nowTime, &packVersion.CreatedAt.Time, &packVersion.UpdatedAt.Time) {
				continue
			}
			if isDependencyOfAVersionNotToDelete(packVersion, versionsNotToDeleteDependencies) {
				continue
			}
			ch <- packVersion
		}
	}()
	return ch
}

func isDependencyOfAVersionNotToDelete(version *github.PackageVersion, versionsNotToDeleteDependencies []string) bool {
	for _, dependency := range versionsNotToDeleteDependencies {
		if dependency == *version.Name {
			return true
		}
	}
	return false
}

func (cleanup *Cleanup) getVersionsNotToDeleteDependencies(packageName string, versionsWithTagsNotToDelete []*github.PackageVersion) (dependencies []string, err error) {
	for _, version := range versionsWithTagsNotToDelete {
		imageRef := "ghcr.io/" + strings.ToLower(gdataOrganisation) + "/" + packageName + ":" + version.Metadata.Container.Tags[0]

		authConfig := registry.AuthConfig{
			Username:      cleanup.registryUsername,
			Password:      cleanup.authToken,
			ServerAddress: "https://ghcr.io/v2/",
		}
		authConfigBytes, _ := json.Marshal(authConfig)
		authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)
		imagePullCloser, error := cleanup.dockerClient.ImagePull(context.Background(), imageRef, image.PullOptions{
			RegistryAuth: authConfigEncoded,
		})
		if error != nil {
			log.Println(error)
			return nil, error
		}
		defer imagePullCloser.Close()
		imageHistory, error := cleanup.dockerClient.ImageHistory(context.Background(), imageRef)
		if error != nil {
			log.Println(error)
			return nil, error
		}
		for _, layer := range imageHistory {
			dependencies = append(dependencies, layer.ID)
		}
	}
	return
}

func areWeAllowedToDeleteThisVersion(version *github.PackageVersion) bool {
	for _, tag := range version.Metadata.Container.Tags {
		if globalTagsNotToDelete.Match([]byte(tag)) {
			return false
		}
	}
	return true
}

func isNewestDateOlderThan2Month(now *time.Time, created *time.Time, updated *time.Time) bool {
	compareTime := updated.AddDate(0, 2, 0)
	if created.After(*updated) {
		compareTime = created.AddDate(0, 2, 0)
	}

	return compareTime.Before(*now)
}

func (cleanup *Cleanup) getContainerPackages(context context.Context, nameRegex *regexp.Regexp) (packageList []*github.Package) {
	run := true
	nextPage := 0
	for run {
		packages, response, err := cleanup.githubClient.Organizations.ListPackages(
			context, gdataOrganisation, &github.PackageListOptions{
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
			if match(nameRegex, pack.Name) {
				packageList = append(packageList, pack)
			}
		}
	}
	return
}

func match(nameRegex *regexp.Regexp, name *string) bool {
	nameByteArray := []byte(*name)
	return nameRegex.Match(nameByteArray)
}
