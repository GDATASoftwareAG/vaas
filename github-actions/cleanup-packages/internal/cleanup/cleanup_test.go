package cleanup

import (
	"github.com/google/go-github/v69/github"
	"testing"
	"time"
)

func TestMatch_Inputgdscanserver_ShouldMatches(t *testing.T) {
	name := []byte("gdscanserver")
	if !globalNameRegex.Match(name) {
		t.Errorf("Name %v should have matched", name)
	}
}

func TestMatch_Inputgdscanserver_ShouldNotMatch(t *testing.T) {
	name := []byte("foobar/gdscanserver")
	if globalNameRegex.Match(name) {
		t.Errorf("Name %v should have matched", name)
	}
}

func TestMatch_Inputgdscanserver1_ShouldNotMatches(t *testing.T) {
	name := []byte("gdscanserver1")
	if globalNameRegex.Match(name) {
		t.Errorf("Name %v should not have matched", name)
	}
}

func TestMatch_Inputvaas_ShouldNotMatches(t *testing.T) {
	name := []byte("vaas")
	if globalNameRegex.Match(name) {
		t.Errorf("Name %v should not have matched", name)
	}
}

func TestMatch_InputvaaswithSlashAndSomethingbehind_ShouldMatches(t *testing.T) {
	name := []byte("vaas/server")
	if !globalNameRegex.Match(name) {
		t.Errorf("Name %v should have matched", name)
	}
}

func TestMatch_InputvaaswithSlashAndNothingbehind_ShouldNotMatches(t *testing.T) {
	name := []byte("vaas/")
	if globalNameRegex.Match(name) {
		t.Errorf("Name %v should have matched", name)
	}
}

var testNowTime = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)

func TestDateCompare_CreatedAndUpdatedAreTheSameAndOlderThan2Month_ShouldReturnTrue(t *testing.T) {
	created := time.Date(2023, 4, 1, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2023, 4, 1, 0, 0, 0, 0, time.UTC)
	if isOlderThan2Month(&testNowTime, &github.PackageVersion{CreatedAt: &github.Timestamp{Time: created}, UpdatedAt: &github.Timestamp{Time: updated}}) {
		t.Error("created and updated are older than 2 month so it should be true")
	}
}

func TestDateCompare_CreatedAndUpdatedAreTheSameAndNotOlderThan2Month_ShouldReturnFalse(t *testing.T) {
	created := time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)
	if isOlderThan2Month(&testNowTime, &github.PackageVersion{CreatedAt: &github.Timestamp{Time: created}, UpdatedAt: &github.Timestamp{Time: updated}}) {
		t.Error("created and updated are not older than 2 month so it should be false")
	}
}

func TestDateCompare_UpdatedIsYoungerAndNotOlderThan2Month_ShouldReturnFalse(t *testing.T) {
	created := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)
	if isOlderThan2Month(&testNowTime, &github.PackageVersion{CreatedAt: &github.Timestamp{Time: created}, UpdatedAt: &github.Timestamp{Time: updated}}) {
		t.Error("updated is not older than 2 month so it should be false")
	}
}

func TestDateCompare_CreatedIsYoungerAndNotOlderThan2Month_ShouldReturnFalse(t *testing.T) {
	created := time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	if isOlderThan2Month(&testNowTime, &github.PackageVersion{CreatedAt: &github.Timestamp{Time: created}, UpdatedAt: &github.Timestamp{Time: updated}}) {
		t.Error("created is not older than 2 month so it should be false")
	}
}

func TestAreWeAllowedToDeleteThisVersion_VersionTagWithSingleNumber_NotAllowed(t *testing.T) {
	tags := []string{"1", "1.1.1-8989"}
	if areWeAllowedToDeleteThisVersion(&github.PackageVersion{Metadata: &github.PackageMetadata{Container: &github.PackageContainerMetadata{Tags: tags}}}) {
		t.Error("this version should not be allowed to delete")
	}
}

func TestAreWeAllowedToDeleteThisVersion_VersionTagWithTrippleNumber_NotAllowed(t *testing.T) {
	tags := []string{"1.1.1", "1.1.1-8989"}
	if areWeAllowedToDeleteThisVersion(&github.PackageVersion{Metadata: &github.PackageMetadata{Container: &github.PackageContainerMetadata{Tags: tags}}}) {
		t.Error("this version should not be allowed to delete")
	}
}

func TestAreWeAllowedToDeleteThisVersion_VersionTagWithLatest_NotAllowed(t *testing.T) {
	tags := []string{"1.1.1-8989", "latest"}
	if areWeAllowedToDeleteThisVersion(&github.PackageVersion{Metadata: &github.PackageMetadata{Container: &github.PackageContainerMetadata{Tags: tags}}}) {
		t.Error("this version should not be allowed to delete")
	}
}

func TestAreWeAllowedToDeleteThisVersion_NoException_Allowed(t *testing.T) {
	tags := []string{"1.1.1-8989", "1-8213"}
	if areWeAllowedToDeleteThisVersion(&github.PackageVersion{Metadata: &github.PackageMetadata{Container: &github.PackageContainerMetadata{Tags: tags}}}) {
		t.Error("this version should not be allowed to delete")
	}
}
