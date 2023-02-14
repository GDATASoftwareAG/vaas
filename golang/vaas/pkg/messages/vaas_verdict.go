package messages

type VaasVerdict struct {
	Verdict Verdict `json:"verdict"`
	Sha256  string  `json:"sha256"`
}
