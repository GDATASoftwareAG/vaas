package messages

type URLAnalysis struct {
	JobId string `json:"id"`
}

type FileAnalysis struct {
	Sha256 string `json:"sha256"`
}
