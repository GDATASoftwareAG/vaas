package messages

type VaasVerdict struct {
	Verdict Verdict
	Sha256  string
	ErrMsg  string
}
