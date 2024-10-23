package messages

type VaasReport struct {
	Sha256  string  `json:"sha256"`
	Verdict Verdict `json:"verdict"`
}

func (r *VaasReport) ConvertToVaasVerdict() VaasVerdict {
	return VaasVerdict{
		Verdict:   r.Verdict,
		Sha256:    r.Sha256,
		ErrMsg:    "", // Set default or handle error messages if needed
		Detection: "", // You can set this based on your logic
		MimeType:  "", // Placeholder for MIME type
		FileType:  "", // Placeholder for file type
	}
}
