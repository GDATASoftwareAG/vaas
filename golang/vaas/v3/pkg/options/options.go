// Package options provides structures and functions for configuring options related to the VaaS client.
package options

type ForSha256Options struct {
	UseHashLookup bool // UseHashLookup Controls whether SHA256 hash lookups are used.
	UseCache      bool // UseCache enables or disables server-side caching.
	VaasRequestId string
}

func NewForSha256Options() ForSha256Options {
	return ForSha256Options{UseCache: true, UseHashLookup: true}
}

type ForFileOptions struct {
	UseHashLookup bool
	UseCache      bool
	VaasRequestId string
}

func NewForFileOptions() ForFileOptions {
	return ForFileOptions{UseCache: true, UseHashLookup: true}
}

type ForStreamOptions struct {
	UseHashLookup bool
	VaasRequestId string
}

func NewForStreamOptions() ForStreamOptions {
	return ForStreamOptions{UseHashLookup: true}
}

type ForUrlOptions struct {
	UseHashLookup bool
	VaasRequestId string
}

func NewForUrlOptions() ForUrlOptions {
	return ForUrlOptions{UseHashLookup: true}
}
