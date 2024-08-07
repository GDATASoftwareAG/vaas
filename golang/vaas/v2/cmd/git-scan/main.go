package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/vaas"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("need 2 parameter: remote, targetBranch")
	}

	remote := os.Args[1]
	if remote == "" {
		log.Fatal("no remote set")
	}
	log.Println("remote:", remote)
	targetBranch := os.Args[2]
	if targetBranch == "" {
		log.Fatal("no targetBranch set")
	}
	log.Println("targetBranch:", targetBranch)

	vaasAuthenticator, credentialsError := getAuthenticator(
		os.Getenv("VAAS_CLIENT_ID"), os.Getenv("VAAS_CLIENT_SECRET"), os.Getenv("VAAS_USERAME"), os.Getenv("VAAS_PASSWORD"))
	if credentialsError != nil {
		log.Fatal(credentialsError)
	}

	vaasUrl, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de/"
	}
	log.Println("vaas url:", vaasUrl)

	gitRevParseCommand := exec.Command("git", "rev-parse", "--show-toplevel")
	rootDirectoryBytes, err := gitRevParseCommand.CombinedOutput()
	if err != nil {
		log.Fatal("git rev-parse: ", err, " ", string(rootDirectoryBytes))
	}
	rootDirectory := strings.Split(strings.ReplaceAll(string(rootDirectoryBytes), "\r\n", "\n"), "\n")[0]
	log.Println("repository root directory: ", rootDirectory)

	fetchBytesCommand := exec.Command("git", "fetch", remote, targetBranch)
	fetchBytes, err := fetchBytesCommand.CombinedOutput()
	if err != nil {
		log.Fatal("git fetch ", err, " ", string(fetchBytes))
	}
	log.Println("fetch result: ", string(fetchBytes))

	gitDiffCommand := exec.Command("git", "diff", "--name-only", remote+"/"+targetBranch)
	diffBytes, err := gitDiffCommand.CombinedOutput()
	if err != nil {
		log.Fatal("git diff ", err, " ", string(diffBytes))
	}
	files := strings.Split(strings.ReplaceAll(string(diffBytes), "\r\n", "\n"), "\n")
	if len(files) < 1 {
		log.Println("no changed files found in diff")
		os.Exit(0)
	}

	vaas := vaas.New(options.DefaultOptions(), vaasUrl)
	ctx, webSocketCancel := context.WithCancel(context.Background())
	termChan, err := vaas.Connect(ctx, vaasAuthenticator)
	if err != nil {
		log.Fatal("vaas connect error: ", err)
	}
	if termChan == nil {
		log.Fatal("vaas connect error")
	}
	var maliciousFileFound bool
	for _, file := range files {
		if file == "" {
			continue
		}
		if _, err := os.Stat(file); err != nil {
			continue
		}
		log.Println("checking file: ", file)
		pathToFile := filepath.Join(rootDirectory, file)
		verdict, err := vaas.ForFile(context.Background(), pathToFile)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println(pathToFile + ": " + string(verdict.Verdict))
		if verdict.Verdict == messages.Malicious {
			maliciousFileFound = true
		}
	}
	webSocketCancel()
	if err = <-termChan; err != nil {
		log.Printf("Websocket shutdown with an error - %v", err)
	}
	if maliciousFileFound {
		os.Exit(1)
	}
}

func getAuthenticator(clientId, clientSecret, username, password string) (vaasAuthenticator authenticator.Authenticator, credentialsError error) {
	tokenUrl, exists := os.LookupEnv("VAAS_TOKEN_URL")
	if !exists {
		tokenUrl = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
	}
	log.Println("token url:", tokenUrl)

	if (clientId != "" && clientSecret != "") || (username != "" && password != "") {
		if username != "" && password != "" {
			vaasAuthenticator = authenticator.NewWithResourceOwnerPassword(username, password, "vaas-github-actions", tokenUrl)
		} else {
			vaasAuthenticator = authenticator.New(clientId, clientSecret, tokenUrl)
		}

		return

	}
	return nil, errors.New("you either need VAAS_CLIENT_ID and VAAS_CLIENT_SECRET or VAAS_USERAME and VAAS_PASSWORD")

}
