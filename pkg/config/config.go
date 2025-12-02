package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config 应用配置
type Config struct {
	Interface  string        `yaml:"interface"`
	QueueID    int           `yaml:"queue_id"`
	QueueCount int           `yaml:"queue_count"`
	BPFPath    string        `yaml:"bpf_path"`
	XDP        XDPConfig     `yaml:"xdp"`
	Workers    WorkerConfig  `yaml:"workers"`
	DNS        DNSConfig     `yaml:"dns"`
	RulesPath  string        `yaml:"rules_path"`
	Metrics    MetricsConfig `yaml:"metrics"`
	Logging    LoggingConfig `yaml:"logging"`
}

// XDPConfig AF_XDP Socket 配置
type XDPConfig struct {
	NumFrames              int `yaml:"num_frames"`
	FrameSize              int `yaml:"frame_size"`
	FillRingNumDescs       int `yaml:"fill_ring_size"`
	CompletionRingNumDescs int `yaml:"comp_ring_size"`
	RxRingNumDescs         int `yaml:"rx_ring_size"`
	TxRingNumDescs         int `yaml:"tx_ring_size"`
}

// WorkerConfig Worker 配置
type WorkerConfig struct {
	NumWorkers int `yaml:"num_workers"`
	BatchSize  int `yaml:"batch_size"`
}

// DNSConfig DNS 配置
type DNSConfig struct {
	ListenPorts     []int    `yaml:"listen_ports"`
	UpstreamServers []string `yaml:"upstream_servers"`
	CacheSize       int      `yaml:"cache_size"`
	CacheTTL        string   `yaml:"cache_ttl"`
}

// MetricsConfig 监控配置
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	if cfg.QueueCount == 0 {
		cfg.QueueCount = 1
	}
	if cfg.Workers.NumWorkers == 0 {
		cfg.Workers.NumWorkers = 4
	}
	if cfg.Workers.BatchSize == 0 {
		cfg.Workers.BatchSize = 32
	}

	return cfg, nil
}

