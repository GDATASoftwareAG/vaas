package messages

type AuthRequest struct {
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	SessionId string `json:"session_id"`
}


