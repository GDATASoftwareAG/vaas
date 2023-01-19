package messages

type AuthRequest struct {
	Kind      string `json:"kind" default:"AuthRequest"` 
	Token     string `json:"token"`
	SessionId string `json:"session_id" default:""`
}
