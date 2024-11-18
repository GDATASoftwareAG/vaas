// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// AuthRequest represents an authentication request sent to the server.
type AuthRequest struct {
	Kind      string `json:"kind" default:"AuthRequest"`
	Token     string `json:"token"`
	SessionID string `json:"session_id" default:""`
}
