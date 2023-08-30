// Package messages provides structures for handling communication messages between the client and the VaaS server.
package messages

// VerdictRequestAttributes represents attributes associated with a verdict request.
type VerdictRequestAttributes struct {
	TenantID string `json:"tenantId"`
}
