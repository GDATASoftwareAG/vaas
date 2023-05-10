package messages

import (
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/google/uuid"
)

type verdictRequest struct {
	Kind      Kind   `json:"kind" default:"VerdictRequest"`
	Sha256    string `json:"sha256"`
	Guid      string `json:"guid"`
	SessionID string `json:"session_id"`
	UseCache  bool   `json:"use_cache"`
	UseShed   bool   `json:"use_shed"`
}

func (r verdictRequest) GetGuid() string {
	return r.Guid
}

func NewVerdictRequest(sessionId string, options options.VaasOptions, sha256 string) VerdictRequest {
	return verdictRequest{
		Kind:      VerdictRequestKind,
		Sha256:    sha256,
		SessionID: sessionId,
		Guid:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}
