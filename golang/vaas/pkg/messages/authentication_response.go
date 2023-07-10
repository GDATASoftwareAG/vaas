package messages

type AuthResponse struct {
	Kind      string `json:"kind"`
	SessionId string `json:"session_id"`
	Text      string `json:"text"`
	Success   bool   `json:"success"`
}
