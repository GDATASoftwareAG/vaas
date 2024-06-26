// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

import (
	"github.com/GDATASoftwareAG/vaas-go/pkg/options"
	"github.com/google/uuid"
)

// VerdictRequestForURL is a specific implementation of VerdictRequest used for URL analysis requests.
type verdictRequestForURL struct {
	Kind                     Kind                     `json:"kind" default:"VerdictRequestForUrl"`
	URL                      string                   `json:"url"`
	GUID                     string                   `json:"guid"`
	SessionID                string                   `json:"session_id"`
	VerdictRequestAttributes VerdictRequestAttributes `json:"verdict_request_attributes"`
	UseCache                 bool                     `json:"use_cache"`
	UseHashLookup            bool                     `json:"use_shed"`
}

// GetGUID returns the GUID of the verdictRequestForURL.
func (r verdictRequestForURL) GetGUID() string {
	return r.GUID
}

// NewVerdictRequestForURL creates a new verdictRequestForURL instance.
func NewVerdictRequestForURL(sessionID string, options options.VaasOptions, URL string) VerdictRequest {
	return verdictRequestForURL{
		Kind:          VerdictRequestForURLKind,
		URL:           URL,
		SessionID:     sessionID,
		GUID:          uuid.New().String(),
		UseCache:      options.UseCache,
		UseHashLookup: options.UseHashLookup,
	}
}

// NewVerdictRequestForURLWithAttributes creates a new verdictRequestForURL instance with attributes.
func NewVerdictRequestForURLWithAttributes(sessionID string, options options.VaasOptions, URL string, attributes VerdictRequestAttributes) VerdictRequest {
	return verdictRequestForURL{
		Kind:                     VerdictRequestForURLKind,
		URL:                      URL,
		SessionID:                sessionID,
		GUID:                     uuid.New().String(),
		UseCache:                 options.UseCache,
		UseHashLookup:            options.UseHashLookup,
		VerdictRequestAttributes: attributes,
	}
}
