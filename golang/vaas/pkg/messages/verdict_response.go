// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// VerdictResponse represents the response containing the verdict information.
type VerdictResponse struct {
	Kind        string  `json:"kind"`
	Sha256      string  `json:"sha256"`
	GUID        string  `json:"guid"`
	Verdict     Verdict `json:"verdict"`
	URL         string  `json:"url"`
	UploadToken string  `json:"upload_token"`
	Detection   string  `json:"detection"`
	FileType    string  `json:"file_type"`
	MimeType    string  `json:"mime_type"`
}

// IsValid checks if the VerdictResponse is valid.
func (response VerdictResponse) IsValid() bool {
	return response.Sha256 != "" && response.Verdict != ""
}
