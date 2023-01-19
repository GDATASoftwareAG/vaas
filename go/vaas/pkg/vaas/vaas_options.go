package vaas

type VaasOptions struct{
	UseShed  bool
	UseCache bool
}

func DefaultOptions() VaasOptions {
	var options VaasOptions
	options.UseCache = false
	options.UseShed = false

	return options
}
