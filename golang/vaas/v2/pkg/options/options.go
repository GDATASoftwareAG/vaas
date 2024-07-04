// Package options provides structures and functions for configuring options related to the VaaS client.
package options

// VaasOptions represents the configuration options for the VaaS client.
type VaasOptions struct {
	UseHashLookup bool // UseHashLookup enables or disables the hash lookup feature.
	UseCache      bool // UseCache enables or disables caching.
	EnableLogs    bool // EnableLogs enables or disables logging.
}

// DefaultOptions returns an instance of VaasOptions with default values.
func DefaultOptions() VaasOptions {
	var options VaasOptions
	options.UseCache = false
	options.UseHashLookup = false

	return options
}
