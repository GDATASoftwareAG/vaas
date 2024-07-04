// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

import (
	"github.com/GDATASoftwareAG/vaas/golang/vaas/v2/pkg/options"
	"github.com/google/uuid"
)

// verdictRequest represents a generic verdict request.
type verdictRequest struct {
	Kind                     Kind                     `json:"kind" default:"VerdictRequest"`
	Sha256                   string                   `json:"sha256"`
	GUID                     string                   `json:"guid"`
	SessionID                string                   `json:"session_id"`
	VerdictRequestAttributes VerdictRequestAttributes `json:"verdict_request_attributes"`
	UseCache                 bool                     `json:"use_cache"`
	UseHashLookup            bool                     `json:"use_shed"`
}

// GetGUID returns the GUID of the verdictRequest.
func (r verdictRequest) GetGUID() string {
	return r.GUID
}

// NewVerdictRequest creates a new verdictRequest instance.
func NewVerdictRequest(sessionID string, options options.VaasOptions, sha256 string) VerdictRequest {
	return verdictRequest{
		Kind:          VerdictRequestKind,
		Sha256:        sha256,
		SessionID:     sessionID,
		GUID:          uuid.New().String(),
		UseCache:      options.UseCache,
		UseHashLookup: options.UseHashLookup,
	}
}

// NewVerdictRequestWithAttributes creates a new verdictRequest instance with attributes.
func NewVerdictRequestWithAttributes(sessionID string, options options.VaasOptions, sha256 string, attributes VerdictRequestAttributes) VerdictRequest {
	return verdictRequest{
		Kind:                     VerdictRequestKind,
		Sha256:                   sha256,
		SessionID:                sessionID,
		GUID:                     uuid.New().String(),
		UseCache:                 options.UseCache,
		UseHashLookup:            options.UseHashLookup,
		VerdictRequestAttributes: attributes,
	}
}
