// Package options provides structures and functions for configuring options related to the VaaS client.
package options

// VaasOptions represents the request configuration options for the VaaS client.
type VaasOptions struct {
	UseHashLookup bool // UseHashLookup Controls whether SHA256 hash lookups are used.
	UseCache      bool // UseCache enables or disables server-side caching.
}

type ForSha256Options struct {
	UseHashLookup bool // UseHashLookup Controls whether SHA256 hash lookups are used.
	UseCache      bool // UseCache enables or disables server-side caching.
}

func (o *ForSha256Options) New() ForSha256Options {
	return ForSha256Options{UseCache: true, UseHashLookup: true}
}

type ForFileOptions struct {
}

type ForStreamOptions struct {
}

type ForUrlOptions struct {
}

// DefaultOptions returns an instance of VaasOptions with default values.
func DefaultOptions() VaasOptions {
	options := VaasOptions{
		UseHashLookup: true,
		UseCache:      true,
	}

	return options
}
