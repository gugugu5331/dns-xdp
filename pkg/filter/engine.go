package filter

import (
	"strings"
	"sync"
)

// Engine 过滤引擎
type Engine struct {
	rules []Rule
	mu    sync.RWMutex
}

// NewEngine 创建过滤引擎
func NewEngine(rulesPath string) (*Engine, error) {
	engine := &Engine{
		rules: make([]Rule, 0),
	}
	return engine, nil
}

// Match 匹配域名
func (e *Engine) Match(domain string) (Action, *Rule) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for i := range e.rules {
		rule := &e.rules[i]
		if matchDomain(domain, rule.Domain) {
			return rule.Action, rule
		}
	}

	return ActionAllow, nil
}

// GetRules 获取所有规则
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule{}, e.rules...)
}

// AddRule 添加规则
func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// matchDomain 匹配域名
func matchDomain(domain, pattern string) bool {
	if pattern == domain {
		return true
	}

	// 支持通配符匹配
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, suffix) || domain == suffix[1:]
	}

	return false
}

