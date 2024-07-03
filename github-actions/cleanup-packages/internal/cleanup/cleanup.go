package cleanup

import (
	"context"
	"log"
	"regexp"
	"time"

	"github.com/google/go-github/v62/github"
)

const gdataOrganisation = "GDATASoftwareAG"

var packageType = "container"
var globalNameRegex, _ = regexp.Compile(`^(gdscanserver|scanclient|vaas/.+)$`)
var globalTagsNotToDelete, _ = regexp.Compile(`^(latest|[0-9]+\.[0-9]+\.[0-9]+|[0-9]+\.[0-9]+|[0-9]+)$`)
var nowTime = time.Now()

// Cleanup the main method of this lib
func Cleanup(client *github.Client) {
	start := time.Now()
	ctx := context.Background()

	packageList := getContainerPackages(ctx, client, globalNameRegex)
	for _, pack := range packageList {
		if pack.GetName() != "vaas/scanner" {
			continue
		}
		println("checking versions for package ", pack.GetName())
		versions := getVersionsOlderThan2Month(ctx, client, pack.Name)
		deleted := 0
		for version := range versions {
			deleted++
			client.Organizations.PackageDeleteVersion(ctx, gdataOrganisation, packageType, pack.GetName(), *version.ID)
		}
		if deleted == 0 {
			log.Println("no versions older than 2 month for package ", pack.GetName())
		}
		log.Printf("Deleted %d Versions for package", deleted)
	}
	log.Printf("Deletion took %s", time.Since(start))
}

func getVersionsOlderThan2Month(context context.Context, client *github.Client, name *string) <-chan *github.PackageVersion {
	ch := make(chan *github.PackageVersion)
	run := true
	nextPage := 1
	packageType := "container"
	_, lengthResponse, err := client.Organizations.PackageGetAllVersions(
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
			packageVersions, response, err := client.Organizations.PackageGetAllVersions(
				context, gdataOrganisation, packageType, *name,
				&github.PackageListOptions{
					ListOptions: github.ListOptions{
						Page:    nextPage,
						PerPage: 100,
					},
					PackageType: &packageType,
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
			for _, packVersion := range packageVersions {
				if isNewestDateOlderThan2Month(&nowTime, &packVersion.CreatedAt.Time, &packVersion.UpdatedAt.Time) {
					if areWeAllowedToDeleteThisVersion(packVersion.Metadata.Container.Tags) {
						ch <- packVersion
					}
				}
			}
		}
	}()
	return ch
}

func areWeAllowedToDeleteThisVersion(tags []string) bool {
	if len(tags) == 0 {
		return false
	}
	for _, tag := range tags {
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

func getContainerPackages(context context.Context, client *github.Client, nameRegex *regexp.Regexp) (packageList []*github.Package) {
	run := true
	nextPage := 0
	for run {
		packages, response, err := client.Organizations.ListPackages(
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
