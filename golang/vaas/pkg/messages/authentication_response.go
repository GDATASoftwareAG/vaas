// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// AuthResponse represents the response to an authentication request.
type AuthResponse struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
	Success   bool   `json:"success"`
}
