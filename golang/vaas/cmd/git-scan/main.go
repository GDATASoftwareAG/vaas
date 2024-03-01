package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/messages"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/vaas"
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

	clientID, exists := os.LookupEnv("VAAS_CLIENT_ID")
	if !exists {
		log.Fatal("no Client ID set")
	}
	clientSecret, exists := os.LookupEnv("VAAS_CLIENT_SECRET")
	if !exists {
		log.Fatal("no Client Secret set")
	}
	vaasUrl, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de/"
	}
	tokenUrl, exists := os.LookupEnv("VAAS_TOKEN_URL")
	if !exists {
		tokenUrl = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
	}

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
	log.Println("found changed files: ", string(diffBytes))

	authenticator := authenticator.New(clientID, clientSecret, tokenUrl)

	vaas := vaas.New(options.DefaultOptions(), vaasUrl)
	ctx, webSocketCancel := context.WithCancel(context.Background())
	termChan, err := vaas.Connect(ctx, authenticator)
	if err != nil {
		log.Fatal("vaas connect error", err)
	}
	if termChan == nil {
		log.Fatal("vaas connect error")
	}
	var maliciousFileFound bool
	for _, file := range files {
		if file != "" {
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
	}
	webSocketCancel()
	if err = <-termChan; err != nil {
		log.Printf("Websocket shutdown with an error - %v", err)
	}
	if maliciousFileFound {
		os.Exit(1)
	}
}
