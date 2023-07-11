package messages

type AuthRequest struct {
	Kind      string `json:"kind" default:"AuthRequest"`
	Token     string `json:"token"`
	SessionID string `json:"session_id" default:""`
}
