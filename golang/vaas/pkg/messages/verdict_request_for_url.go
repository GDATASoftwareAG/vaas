package messages

import (
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/google/uuid"
)

type verdictRequestForUrl struct {
	Kind                     Kind                     `json:"kind" default:"VerdictRequestForUrl"`
	Url                      string                   `json:"url"`
	Guid                     string                   `json:"guid"`
	SessionID                string                   `json:"session_id"`
	UseCache                 bool                     `json:"use_cache"`
	UseShed                  bool                     `json:"use_shed"`
	VerdictRequestAttributes VerdictRequestAttributes `json:"verdict_request_attributes"`
}

func (r verdictRequestForUrl) GetGuid() string {
	return r.Guid
}

func NewVerdictRequestForUrl(sessionId string, options options.VaasOptions, url string) VerdictRequest {
	return verdictRequestForUrl{
		Kind:      VerdictRequestForUrlKind,
		Url:       url,
		SessionID: sessionId,
		Guid:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}

func NewVerdictRequestForUrlWithAttributes(sessionId string, options options.VaasOptions, url string, attributes VerdictRequestAttributes) VerdictRequest {
	return verdictRequestForUrl{
		Kind:                     VerdictRequestForUrlKind,
		Url:                      url,
		SessionID:                sessionId,
		Guid:                     uuid.New().String(),
		UseCache:                 options.UseCache,
		UseShed:                  options.UseShed,
		VerdictRequestAttributes: attributes,
	}
}
