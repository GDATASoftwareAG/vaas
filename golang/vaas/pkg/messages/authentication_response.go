package messages

type AuthResponse struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
	Success   bool   `json:"success"`
}
