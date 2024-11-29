package messages

type FileReport struct {
	Sha256    string  `json:"sha256" validate:"required"`
	Verdict   Verdict `json:"verdict" validate:"required"`
	Detection string  `json:"detection,omitempty"`
	MimeType  string  `json:"mimetype,omitempty"`
	FileType  string  `json:"file_type,omitempty"`
}

func (r *FileReport) ConvertToVaasVerdict() VaasVerdict {
	return VaasVerdict{
		Verdict:   r.Verdict,
		Sha256:    r.Sha256,
		Detection: r.Detection,
		MimeType:  r.MimeType,
		FileType:  r.FileType,
	}
}

type URLReport struct {
	Sha256    string  `json:"sha256" validate:"required"`
	Verdict   Verdict `json:"verdict" validate:"required"`
	Detection string  `json:"detection,omitempty"`
	MimeType  string  `json:"mimetype,omitempty"`
	FileType  string  `json:"file_type,omitempty"`
	URL       string  `json:"url" validate:"required"`
}

func (r *URLReport) ConvertToVaasVerdict() VaasVerdict {
	return VaasVerdict{
		Verdict:   r.Verdict,
		Sha256:    r.Sha256,
		Detection: r.Detection,
		MimeType:  r.MimeType,
		FileType:  r.FileType,
	}
}
