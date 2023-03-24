package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/joho/godotenv"

	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/authenticator"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/vaas"

	credentials "github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/credentials"
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
)

var sha256Check = flag.Bool("s", false, "sha256")
var fileCheck = flag.Bool("f", false, "file")
var urlCheck = flag.Bool("u", false, "url")

func main() {
	flag.Parse()

	if err := godotenv.Load(); err != nil {
		log.Printf("failed to load environment - %v", err)
	}
	CLIENT_ID, CLIENT_SECRET, VAAS_URL, TOKEN_ENDPOINT := credentials.ReadCredentials()
	authenticator := authenticator.New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)

	var accessToken string
	if err := authenticator.GetToken(&accessToken); err != nil {
		log.Fatal(err)
	}

	vaasClient := vaas.New(options.VaasOptions{
		UseShed:  true,
		UseCache: false,
	}, VAAS_URL)
	ctx := context.Background()
	if err := vaasClient.Connect(ctx, accessToken); err != nil {
		log.Fatal("Something went wrong", err.Error())
	}

	if *sha256Check {
		sha256List := flag.Args()
		if err := checkSha256(sha256List, vaasClient); err != nil {
			log.Fatal(err)
		}
	}

	if *urlCheck {
		urlList := flag.Args()
		if err := checkUrl(urlList, vaasClient); err != nil {
			log.Fatal(err)
		}
	}

	if *fileCheck {
		fileList := flag.Args()
		if err := checkFile(fileList, vaasClient); err != nil {
			log.Fatal(err)
		}
	}
}

func checkFile(fileList []string, vaasClient vaas.Vaas) error {
	if len(fileList) == 0 {
		log.Fatal("no file entered in arguments")

	} else if len(fileList) == 1 {
		result, err := vaasClient.ForFile(fileList[0])
		if err != nil {
			return err
		}
		fmt.Println(result.Verdict)

	} else if len(fileList) > 1 {
		results, err := vaasClient.ForFileList(fileList)
		if err != nil {
			return err
		}

		for _, result := range results {
			fmt.Println(result.Sha256, result.Verdict)
		}
	}
	return nil
}

func checkSha256(sha256List []string, vaasClient vaas.Vaas) error {
	if len(sha256List) == 0 {
		log.Fatal("no sha256 entered in arguments")
	}
	if len(sha256List) == 1 {
		result, err := vaasClient.ForSha256(sha256List[0])
		if err != nil {
			return err
		}
		fmt.Println(result.Verdict)

	} else if len(sha256List) > 1 {
		results, err := vaasClient.ForSha256List(sha256List)
		if err != nil {
			return err
		}

		for _, verdict := range results {
			fmt.Println(verdict.Sha256, verdict.Verdict)
		}
	}
	return nil
}

func checkUrl(urlList []string, vaasClient vaas.Vaas) error {
	if len(urlList) == 0 {
		log.Fatal("no url entered in arguments")
	}

	if len(urlList) == 1 {
		result, err := vaasClient.ForUrl(urlList[0])
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
				result, err := vaasClient.ForUrl(url)
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
