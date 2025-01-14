package messages

type URLAnalysisRequest struct {
	Url           string `json:"url"`
	UseHashLookup bool   `json:"useHashLookup"`
}
