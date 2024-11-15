package messages

type VaasReport struct {
	Sha256    string  `json:"sha256"`
	Verdict   Verdict `json:"verdict"`
	Detection string  `json:"detection,omitempty"`
	MimeType  string  `json:"mimetype,omitempty"`
	FileType  string  `json:"file_type,omitempty"`
}

func (r *VaasReport) ConvertToVaasVerdict() VaasVerdict {
	return VaasVerdict{
		Verdict:   r.Verdict,
		Sha256:    r.Sha256,
		Detection: r.Detection,
		MimeType:  r.MimeType,
		FileType:  r.FileType,
	}
}
