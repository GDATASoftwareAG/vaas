package messages

type VerdictResponse struct {
	Kind        string  `json:"kind"`
	Sha256      string  `json:"sha256"`
	GUID        string  `json:"guid"`
	Verdict     Verdict `json:"verdict"`
	URL         string  `json:"url"`
	UploadToken string  `json:"upload_token"`
}

func (response VerdictResponse) IsValid() bool {
	return response.Sha256 != "" && response.Verdict != ""
}
