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

type cleanup struct {
	githubClient     *github.Client
	dockerClient     *client.Client
	authToken        string
	registryUsername string
}

func NewCleanup(githubClient *github.Client, dockerClient *client.Client, authToken string, registryUsername string) *cleanup {
	cleanup := cleanup{
		githubClient:     githubClient,
		dockerClient:     dockerClient,
		authToken:        authToken,
		registryUsername: registryUsername,
	}
	return &cleanup
}

func (cleanup *cleanup) Run(context context.Context) {
	start := time.Now()

	packageList := cleanup.getContainerPackages(context, globalNameRegex)
	for _, pack := range packageList {
		println("checking versions for package ", pack.GetName())
		versions := cleanup.getVersionsOlderThan2Month(context, pack.Name)
		deleted := 0
		for version := range versions {
			deleted++
			log.Printf(
				"deleting package %v with versions %v created %v updates %v",
				pack.GetName(), strings.Join(version.Metadata.Container.Tags, "|"),
				version.CreatedAt.Time, version.UpdatedAt.Time)
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

func (cleanup *cleanup) getVersionsOlderThan2Month(context context.Context, name *string) <-chan *github.PackageVersion {
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

		var versionsNotToDeleteDependencies = cleanup.getVersionsNotToDeleteDependencies(*name, versionsWithTagsNotToDelete)
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

func (cleanup *cleanup) getVersionsNotToDeleteDependencies(packageName string, versionsWithTagsNotToDelete []*github.PackageVersion) (dependencies []string) {
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
		} else {
			defer imagePullCloser.Close()
		}
		imageHistory, _ := cleanup.dockerClient.ImageHistory(context.Background(), imageRef)
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

func (cleanup *cleanup) getContainerPackages(context context.Context, nameRegex *regexp.Regexp) (packageList []*github.Package) {
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
