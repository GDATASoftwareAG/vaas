package vaas

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"

	"vaas/pkg/authenticator"
	credentials "vaas/pkg/credentials"
	"vaas/pkg/messages"
	"vaas/pkg/options"
	"vaas/pkg/vaas"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

var VaasClient vaas.Vaas
var AccessToken string

func setUp() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	CLIENT_ID, CLIENT_SECRET, VAAS_URL, TOKEN_ENDPOINT := credentials.ReadCredentials()
	authenticator := authenticator.New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)

	var accessToken string
	if err := authenticator.GetToken(&accessToken); err != nil {
		log.Fatal(err)
	}

	testingOptions := options.VaasOptions{
		UseShed:  true,
		UseCache: false,
	}
	VaasClient = vaas.New(testingOptions, VAAS_URL)
	AccessToken = accessToken

	err := VaasClient.Connect(AccessToken)
	if err != nil {
		log.Fatal(err)
	}
}

func TestForSha256_InvalidOperation(t *testing.T) {
	testingOptions := options.VaasOptions{
		UseShed:  true,
		UseCache: false,
	}
	vaas := vaas.New(testingOptions, "")

	_, err := vaas.ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")

	assert.NotEqual(t, err, nil)
}

func TestForSha256_SingleMaliciousHash(t *testing.T) {
	setUp()
	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"

	verdict, err := VaasClient.ForSha256(maliciousSha256)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Malicious))
}

func TestForSha256_SingleCleanHash(t *testing.T) {
	setUp()
	cleanSha256 := "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"

	verdict, err := VaasClient.ForSha256(cleanSha256)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Clean))
}

func TestForSha256_SingleUnknownHash(t *testing.T) {
	setUp()
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"

	verdict, err := VaasClient.ForSha256(unknownSha256)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Unknown))
}

func TestForSha256List_MultipleHashes_CleanMaliciousUnknown(t *testing.T) {
	setUp()
	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
	cleanSha256 := "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"

	verdicts, err := VaasClient.ForSha256List([]string{maliciousSha256, cleanSha256, unknownSha256})
	if err != nil {
		log.Fatal(err)
	}

	maliciousIndex := Index(verdicts, maliciousSha256)
	unknownIndex := Index(verdicts, unknownSha256)
	cleanIndex := Index(verdicts, cleanSha256)

	assert.Equal(t, verdicts[maliciousIndex].Verdict, messages.Verdict(messages.Malicious))
	assert.Equal(t, verdicts[cleanIndex].Verdict, messages.Verdict(messages.Clean))
	assert.Equal(t, verdicts[unknownIndex].Verdict, messages.Verdict(messages.Unknown))
}

func TestForFile_RandomGeneratedUnknown_Clean(t *testing.T) {
	setUp()
	randomString := RandomString(200)

	err := os.WriteFile("cleanFile", []byte(randomString), 0644)
	if err != nil {
		t.Fatalf("error while writing clean file: %v", err)
	}
	defer os.Remove("cleanFile")

	verdict, err := VaasClient.ForFile("cleanFile")
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Clean))
}

func TestForFileList_MultipleRandomGeneratedFiles_AllClean(t *testing.T) {
	setUp()
	var randomFiles []string
	for i := 0; i < 3; i++ {
		filename := "cleanFile" + fmt.Sprint(i)
		err := os.WriteFile(filename, []byte(RandomString(200)), 0644)
		if err != nil {
			t.Fatalf("error while writing clean file: %v", err)
		}
		randomFiles = append(randomFiles, filename)
	}

	verdicts, err := VaasClient.ForFileList(randomFiles)
	if err != nil {
		log.Fatal(err)
	}

	for _, verdict := range verdicts {
		assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Clean))
	}

	for _, file := range randomFiles {
		os.Remove(file)
	}
}

func TestForUrl_CleanFile_Clean(t *testing.T) {
	setUp()
	cleanUrl := "https://random-data-api.com/api/v2/beers"
	verdict, err := VaasClient.ForUrl(cleanUrl)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Clean))
}

func TestForUrl_EicarFile_Malicious(t *testing.T) {
	setUp()
	eicarUrl := "https://secure.eicar.org/eicar.com"

	verdict, err := VaasClient.ForUrl(eicarUrl)
	if err != nil {
		log.Fatal(err)
	}

	assert.Equal(t, verdict.Verdict, messages.Verdict(messages.Malicious))
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func Index(s []messages.VaasVerdict, str string) int {
	for i, v := range s {
		if v.Sha256 == str {
			return i
		}
	}

	return -1
}
