package citadel

type Config struct {
	apiKey       string
	preSharedKey string
}

func NewPreSharedKeyConfig(preSharedKey string) Config {
	return Config{
		preSharedKey: preSharedKey,
	}
}

func NewAPIKeyConfig(apiKey string, preSharedKey string) Config {
	return Config{
		apiKey:       apiKey,
		preSharedKey: preSharedKey,
	}
}
