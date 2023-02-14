package messages

type AuthResponse struct {
	Kind      string `json:"kind"`
	Success   bool   `json:"success"`
	SessionId string `json:"session_id"`
	Text      string `json:"text"`
}
