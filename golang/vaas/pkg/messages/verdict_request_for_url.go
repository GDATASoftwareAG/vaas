package messages

import (
	"github.com/google/uuid"
	"vaas/pkg/options"
)

type VerdictRequestForUrl struct {
	Kind      Kind   `json:"kind" default:"VerdictRequestForUrl"`
	Url       string `json:"url"`
	Guid      string `json:"guid"`
	SessionID string `json:"session_id"`
	UseCache  bool   `json:"use_cache"`
	UseShed   bool   `json:"use_shed"`
}

func (r VerdictRequestForUrl) GetGuid() string {
	return r.Guid
}

func NewVerdictRequestForUrl(sessionId string, options options.VaasOptions, url string) VerdictRequest {
	return VerdictRequestForUrl{
		Kind:      VerdictRequestForUrlKind,
		Url:       url,
		SessionID: sessionId,
		Guid:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}
