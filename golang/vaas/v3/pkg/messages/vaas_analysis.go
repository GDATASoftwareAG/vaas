package messages

type URLAnalysis struct {
	JobId string `json:"id" validate:"required"`
}

type FileAnalysis struct {
	Sha256 string `json:"sha256" validate:"required"`
}
