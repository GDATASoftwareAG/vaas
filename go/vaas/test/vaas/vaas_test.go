package vaas_test

import (
	"log"
	"testing"

	"vaas/pkg/authenticator"
	"vaas/pkg/messages"
	"vaas/pkg/options"
	"vaas/pkg/vaas"
	utilities "vaas/test/test_utilities"

	"github.com/joho/godotenv"
)

var VaasClient vaas.Vaas
var AccessToken string

func setUp() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT := utilities.ReadCredentials()
	authenticator := authenticator.New(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)

	var accessToken string
	if err := authenticator.GetToken(&accessToken); err != nil {
		log.Fatal(err)
	}

	testingOptions := options.VaasOptions{
		UseShed:  true,
		UseCache: false,
	}

	VaasClient = *vaas.New(testingOptions)
	AccessToken = accessToken

	err := VaasClient.Connect(AccessToken)
	if err != nil {
		log.Fatal(err)
	}
}

func TestForSha256_InvalidOperation(t *testing.T) {
	var vaas vaas.Vaas
	_, err := vaas.ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
	if err == nil {
		t.Errorf(`%q, expected err = "invalid operation"`, err)
	}
}

func TestForSha256_SingleMaliciousHash(t *testing.T) {
	setUp()
	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
	verdict, err := VaasClient.ForSha256(maliciousSha256)

	malicious := verdict.Verdict == messages.Verdict(messages.Malicious)

	if err != nil || !malicious {
		t.Fatalf(`VaasClient.ForSha256(%q) = %q. %v, want "Malicious", nil`, maliciousSha256, verdict.Verdict, err)
	}
}

func TestForSha256_SingleCleanHash(t *testing.T) {
	setUp()
	cleanSha256 := "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"
	verdict, err := VaasClient.ForSha256(cleanSha256)

	clean := verdict.Verdict == messages.Verdict(messages.Clean)
	if err != nil || !clean {
		t.Fatalf(`VaasClient.ForSha256(%q) = %q. %v, want "Malicious", nil`, cleanSha256, verdict.Verdict, err)
	}
}

func TestForSha256_SingleUnknownHash(t *testing.T) {
	setUp()
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"
	verdict, err := VaasClient.ForSha256(unknownSha256)

	unknown := verdict.Verdict == messages.Verdict(messages.Unknown)

	if err != nil || !unknown {
		t.Fatalf(`VaasClient.ForSha256(%q) = %q. %v, want "Malicious", nil`, unknownSha256, verdict.Verdict, err)
	}
}

func TestForSha256List_MultipleHashes_CleanMaliciousUnknown(t *testing.T) {
	setUp()
	maliciousSha256 := "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
	cleanSha256 := "698cda840a0b3d4639f0c5dbd5c629a847a27448a9a179cb6b7a648bc1186f23"
	unknownSha256 := "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"

	verdicts, err := VaasClient.ForSha256List([]string{maliciousSha256, cleanSha256, unknownSha256})

	maliciousIndex := utilities.Index(verdicts, maliciousSha256)
	unknownIndex := utilities.Index(verdicts, unknownSha256)
	cleanIndex := utilities.Index(verdicts, cleanSha256)
	log.Println(maliciousIndex, unknownIndex, cleanIndex, err)
	if verdicts[maliciousIndex].Verdict != messages.Verdict(messages.Malicious) ||
		verdicts[unknownIndex].Verdict != messages.Verdict(messages.Unknown) ||
		verdicts[cleanIndex].Verdict != messages.Verdict(messages.Clean) ||
		err != nil {
			t.Fatalf(`VaasClient.ForSha256List([]string{%q,%q,%q} = %q, want verdicts "Clean", "Unknown" and "Malicious", nil`, 
				cleanSha256, unknownSha256, maliciousSha256, err)
	}
}
