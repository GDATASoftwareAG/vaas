package messages

import (
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/google/uuid"
)

type verdictRequest struct {
	Kind                     Kind                     `json:"kind" default:"VerdictRequest"`
	Sha256                   string                   `json:"sha256"`
	GUID                     string                   `json:"guid"`
	SessionID                string                   `json:"session_id"`
	VerdictRequestAttributes VerdictRequestAttributes `json:"verdict_request_attributes"`
	UseCache                 bool                     `json:"use_cache"`
	UseShed                  bool                     `json:"use_shed"`
}

func (r verdictRequest) GetGUID() string {
	return r.GUID
}

func NewVerdictRequest(sessionID string, options options.VaasOptions, sha256 string) VerdictRequest {
	return verdictRequest{
		Kind:      VerdictRequestKind,
		Sha256:    sha256,
		SessionID: sessionID,
		GUID:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}

func NewVerdictRequestWithAttributes(sessionID string, options options.VaasOptions, sha256 string, attributes VerdictRequestAttributes) VerdictRequest {
	return verdictRequest{
		Kind:                     VerdictRequestKind,
		Sha256:                   sha256,
		SessionID:                sessionID,
		GUID:                     uuid.New().String(),
		UseCache:                 options.UseCache,
		UseShed:                  options.UseShed,
		VerdictRequestAttributes: attributes,
	}
}
