package options

type VaasOptions struct {
	UseShed    bool
	UseCache   bool
	EnableLogs bool
}

func DefaultOptions() VaasOptions {
	var options VaasOptions
	options.UseCache = false
	options.UseShed = false

	return options
}
