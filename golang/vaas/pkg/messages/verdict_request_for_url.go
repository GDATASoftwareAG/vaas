package messages

import (
	"github.com/GDATASoftwareAG/vaas/golang/vaas/pkg/options"
	"github.com/google/uuid"
)

type verdictRequestForURL struct {
	Kind                     Kind                     `json:"kind" default:"VerdictRequestForUrl"`
	URL                      string                   `json:"URL"`
	GUID                     string                   `json:"guid"`
	SessionID                string                   `json:"session_id"`
	VerdictRequestAttributes VerdictRequestAttributes `json:"verdict_request_attributes"`
	UseCache                 bool                     `json:"use_cache"`
	UseShed                  bool                     `json:"use_shed"`
}

func (r verdictRequestForURL) GetGUID() string {
	return r.GUID
}

func NewVerdictRequestForURL(sessionId string, options options.VaasOptions, URL string) VerdictRequest {
	return verdictRequestForURL{
		Kind:      VerdictRequestForURLKind,
		URL:       URL,
		SessionID: sessionId,
		GUID:      uuid.New().String(),
		UseCache:  options.UseCache,
		UseShed:   options.UseShed,
	}
}

func NewVerdictRequestForUrlWithAttributes(sessionId string, options options.VaasOptions, URL string, attributes VerdictRequestAttributes) VerdictRequest {
	return verdictRequestForURL{
		Kind:                     VerdictRequestForURLKind,
		URL:                      URL,
		SessionID:                sessionId,
		GUID:                     uuid.New().String(),
		UseCache:                 options.UseCache,
		UseShed:                  options.UseShed,
		VerdictRequestAttributes: attributes,
	}
}
