package metrics

import "sync/atomic"

// Collector 指标收集器
type Collector struct {
	totalPackets  uint64
	dnsPackets    uint64
	allowed       uint64
	blocked       uint64
	redirected    uint64
	logged        uint64
}

// NewCollector 创建指标收集器
func NewCollector() *Collector {
	return &Collector{}
}

// IncTotalPackets 增加总数据包计数
func (c *Collector) IncTotalPackets() {
	atomic.AddUint64(&c.totalPackets, 1)
}

// IncDNSPackets 增加 DNS 数据包计数
func (c *Collector) IncDNSPackets() {
	atomic.AddUint64(&c.dnsPackets, 1)
}

// IncAllowed 增加允许计数
func (c *Collector) IncAllowed() {
	atomic.AddUint64(&c.allowed, 1)
}

// IncBlocked 增加阻止计数
func (c *Collector) IncBlocked() {
	atomic.AddUint64(&c.blocked, 1)
}

// IncRedirected 增加重定向计数
func (c *Collector) IncRedirected() {
	atomic.AddUint64(&c.redirected, 1)
}

// IncLogged 增加日志计数
func (c *Collector) IncLogged() {
	atomic.AddUint64(&c.logged, 1)
}

// GetMetrics 获取所有指标
func (c *Collector) GetMetrics() map[string]uint64 {
	return map[string]uint64{
		"total_packets": atomic.LoadUint64(&c.totalPackets),
		"dns_packets":   atomic.LoadUint64(&c.dnsPackets),
		"allowed":       atomic.LoadUint64(&c.allowed),
		"blocked":       atomic.LoadUint64(&c.blocked),
		"redirected":    atomic.LoadUint64(&c.redirected),
		"logged":        atomic.LoadUint64(&c.logged),
	}
}

