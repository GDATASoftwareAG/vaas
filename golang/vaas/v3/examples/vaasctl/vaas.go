package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/vaas"
)

var sha256Check = flag.Bool("s", false, "sha256")
var fileCheck = flag.Bool("f", false, "file")
var urlCheck = flag.Bool("u", false, "url")

func main() {
	flag.Parse()

	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}
	clientID, exists := os.LookupEnv("CLIENT_ID")
	if !exists {
		log.Fatal("no Client ID set")
	}
	clientSecret, exists := os.LookupEnv("CLIENT_SECRET")
	if !exists {
		log.Fatal("no Client Secret set")
	}
	tokenEndpoint, exists := os.LookupEnv("TOKEN_URL")
	if !exists {
		tokenEndpoint = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
	}
	vaasURLString, exists := os.LookupEnv("VAAS_URL")
	if !exists {
		vaasURLString = "wss://gateway.production.vaas.gdatasecurity.de"
	}
	vaasURL, err := url.Parse(vaasURLString)
	if err != nil {
		log.Fatal("VAAS_URL is not an URL")
	}

	auth := authenticator.New(clientID, clientSecret, tokenEndpoint)

	vaasClient := vaas.New(options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
		EnableLogs:    false,
	}, vaasURL, auth)

	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer analysisCancel()

	if *sha256Check {
		sha256List := flag.Args()
		if err := checkSha256(analysisCtx, sha256List, vaasClient); err != nil {
			log.Fatal(err)
		}
	}

	if *urlCheck {
		urlList := flag.Args()
		if err := checkURL(analysisCtx, urlList, vaasClient); err != nil {
			log.Fatal(err)
		}
	}

	if *fileCheck {
		fileList := flag.Args()
		if err := checkFile(analysisCtx, fileList, vaasClient); err != nil {
			log.Fatal(err)
		}
	}
}

func checkFile(ctx context.Context, fileList []string, vaasClient vaas.Vaas) error {
	if len(fileList) == 0 {
		log.Fatal("no file entered in arguments")
	}

	for _, file := range fileList {
		result, err := vaasClient.ForFile(ctx, file)
		if err != nil {
			log.Printf("%s: %s", file, err.Error())
			continue
		}
		fmt.Println(file, result.Sha256, result.Verdict, result.Detection)
	}
	return nil
}

func checkSha256(ctx context.Context, sha256List []string, vaasClient vaas.Vaas) error {
	if len(sha256List) == 0 {
		log.Fatal("no sha256 entered in arguments")
	}
	for _, sha256 := range sha256List {
		result, err := vaasClient.ForSha256(ctx, sha256)
		if err != nil {
			log.Printf("%s: %s", sha256, err.Error())
			continue
		}
		fmt.Println(sha256, result.Verdict)
	}

	return nil
}

func checkURL(ctx context.Context, urlList []string, vaasClient vaas.Vaas) error {
	if len(urlList) == 0 {
		log.Fatal("no url entered in arguments")
	}

	if len(urlList) == 1 {
		result, err := vaasClient.ForUrl(ctx, urlList[0])
		if err != nil {
			return err
		}
		fmt.Println(result.Verdict)

	} else if len(urlList) > 1 {
		var waitGroup sync.WaitGroup
		for _, u := range urlList {
			waitGroup.Add(1)
			go func(url string) {
				defer waitGroup.Done()
				result, err := vaasClient.ForUrl(ctx, url)
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println(result)
				}
			}(u)
		}
		waitGroup.Wait()
	}
	return nil
}
