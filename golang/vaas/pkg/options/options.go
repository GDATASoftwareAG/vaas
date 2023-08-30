package options

type VaasOptions struct {
	UseHashLookup bool
	UseCache      bool
	EnableLogs    bool
}

func DefaultOptions() VaasOptions {
	var options VaasOptions
	options.UseCache = false
	options.UseHashLookup = false

	return options
}
