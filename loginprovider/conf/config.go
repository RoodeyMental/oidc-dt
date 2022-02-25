package conf

type Config struct {
	Database struct {
		Hostname   string `yaml:"host"`
		DriverType string `yaml:"drivertype"`
		Password   string `yaml:"password"`
		Username   string `yaml:"username"`
		Port       string `yaml:"port"`
		Schema     string `yaml:"schema"`
	} `yaml:"database"`
	OPA struct {
		Hostname string `yaml:"host"`
		Port     string `yaml:"port"`
	} `yaml:"opa"`
	Hydra struct {
		Hostname string `yaml:"host"`
		Port     string `yaml:"port"`
	} `yaml:"hydra"`
}
