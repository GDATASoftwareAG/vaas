package messages

import "hash"

type VerdictRequest struct {
	Kind      string    `json:"kind" default:"VerdictRequest"`
	Sha256    hash.Hash `json:"sha256"`
	Guid      string    `json:"guid"`
	SessionID string    `json:"session_id"`
	UseCache  bool      `json:"use_cache"`
	UseShed   bool      `json:"use_shed"`
}
