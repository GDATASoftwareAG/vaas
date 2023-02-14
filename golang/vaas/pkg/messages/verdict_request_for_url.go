package messages

import (
	"github.com/google/uuid"
	"vaas/pkg/options"
)

type VerdictRequestForUrl struct {
	Kind      string `json:"kind" default:"VerdictRequestForUrl"`
	Url       string `json:"url"`
	Guid      string `json:"guid"`
	SessionID string `json:"session_id"`
	UseCache  bool   `json:"use_cache"`
	UseShed   bool   `json:"use_shed"`
}

func (r VerdictRequestForUrl) GetSessionId() string {
	return r.SessionID
}

func (r VerdictRequestForUrl) New(sessionId string, options options.VaasOptions, url string) VerdictRequestForUrl {
	return VerdictRequestForUrl{
		Kind:      "VerdictRequestForUrl",
		Url:       url,
		SessionID: sessionId,
		Guid:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}
