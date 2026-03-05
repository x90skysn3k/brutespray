package modules

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds settings loadable from a YAML config file.
// CLI flags override config file values.
type Config struct {
	User            string        `yaml:"user"`
	Password        string        `yaml:"password"`
	Combo           string        `yaml:"combo"`
	Output          string        `yaml:"output"`
	Threads         int           `yaml:"threads"`
	HostParallelism int           `yaml:"host_parallelism"`
	Timeout         time.Duration `yaml:"timeout"`
	Retry           int           `yaml:"retry"`
	Service         string        `yaml:"service"`
	Socks5          string        `yaml:"socks5"`
	Interface       string        `yaml:"interface"`
	Domain          string        `yaml:"domain"`
	RateLimit       float64       `yaml:"rate"`
	StopOnSuccess   bool          `yaml:"stop_on_success"`
	Silent          bool          `yaml:"silent"`
	LogEvery        int           `yaml:"log_every"`
	Summary         bool          `yaml:"summary"`
	NoColor         bool          `yaml:"no_color"`
	Spray           bool          `yaml:"spray"`
	SprayDelay      time.Duration `yaml:"spray_delay"`
	Hosts           []string      `yaml:"hosts"`
	File            string        `yaml:"file"`
}

// LoadConfig reads a YAML config file and returns the parsed config.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}
