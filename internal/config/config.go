package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SSL struct {
		Enabled       bool   `yaml:"enabled"`
		WSAddr        string `yaml:"ws_addr"`
		WSOrigin      string `yaml:"ws_origin"`
		RetryInterval string `yaml:"retry_interval"`
	} `yaml:"ssl"`
	CommandEBPF struct {
		Enabled   bool   `yaml:"enabled"`
		ClaudeBin string `yaml:"claude_bin"`
	} `yaml:"command_ebpf"`
}

func Load(path string) (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

func (c Config) RetryDuration() time.Duration {
	d, err := time.ParseDuration(c.SSL.RetryInterval)
	if err != nil || d <= 0 {
		return 5 * time.Second
	}
	return d
}

func defaultConfig() Config {
	var cfg Config
	cfg.SSL.Enabled = true
	cfg.SSL.WSAddr = "127.0.0.1:28257"
	cfg.SSL.WSOrigin = "http://localhost/"
	cfg.SSL.RetryInterval = "5s"
	cfg.CommandEBPF.Enabled = false
	cfg.CommandEBPF.ClaudeBin = ""
	return cfg
}
