package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/vaas"
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

	auth := authenticator.NewWithDefaultTokenEndpoint(clientID, clientSecret)

	vaasClient := vaas.NewWithDefaultEndpoint(options.VaasOptions{
		UseHashLookup: true,
		UseCache:      false,
		EnableLogs:    false,
	})
	connectCtx, webSocketCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer webSocketCancel()

	termChan, err := vaasClient.Connect(connectCtx, auth)
	if err != nil {
		log.Fatalf("failed to connect to VaaS %s", err.Error())
	}

	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	if err = vaasClient.Close(); err != nil {
		log.Printf("unable to close VaasClient - %v", err)
	}
	if err = <-termChan; err != nil {
		log.Printf("Websocket shutdown with an error - %v", err)
	}
}

func checkFile(ctx context.Context, fileList []string, vaasClient vaas.Vaas) error {
	if len(fileList) == 0 {
		log.Fatal("no file entered in arguments")

	} else if len(fileList) == 1 {
		result, err := vaasClient.ForFile(ctx, fileList[0])
		if err != nil {
			return err
		}
		fmt.Println(result.Verdict)

	} else if len(fileList) > 1 {
		results, err := vaasClient.ForFileList(ctx, fileList)
		if err != nil {
			return err
		}

		for _, result := range results {
			fmt.Println(result.Sha256, result.Verdict)
		}
	}
	return nil
}

func checkSha256(ctx context.Context, sha256List []string, vaasClient vaas.Vaas) error {
	if len(sha256List) == 0 {
		log.Fatal("no sha256 entered in arguments")
	}
	if len(sha256List) == 1 {
		result, err := vaasClient.ForSha256(ctx, sha256List[0])
		if err != nil {
			return err
		}
		fmt.Println(result.Verdict)

	} else if len(sha256List) > 1 {
		results, err := vaasClient.ForSha256List(ctx, sha256List)
		if err != nil {
			return err
		}

		for _, verdict := range results {
			fmt.Println(verdict.Sha256, verdict.Verdict)
		}
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
		for _, url := range urlList {
			waitGroup.Add(1)
			go func(url string) {
				defer waitGroup.Done()
				result, err := vaasClient.ForUrl(ctx, url)
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println(result)
				}
			}(url)
		}
		waitGroup.Wait()
	}
	return nil
}
