// Package options provides structures and functions for configuring options related to the VaaS client.
package options

// VaasOptions represents the request configuration options for the VaaS client.
type VaasOptions struct {
	UseHashLookup bool // UseHashLookup Controls whether SHA256 hash lookups are used.
	UseCache      bool // UseCache enables or disables server-side caching.
}

// DefaultOptions returns an instance of VaasOptions with default values.
func DefaultOptions() VaasOptions {
	options := VaasOptions{
		UseHashLookup: true,
		UseCache:      true,
	}

	return options
}
