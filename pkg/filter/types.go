package filter

import "net"

// Action 过滤动作
type Action int

const (
	ActionAllow    Action = iota // 允许
	ActionBlock                  // 阻止
	ActionRedirect               // 重定向
	ActionLog                    // 仅记录
)

// Rule 过滤规则
type Rule struct {
	ID          string   // 规则 ID
	Domain      string   // 域名模式
	Action      Action   // 动作
	RedirectIP  net.IP   // 重定向 IP (用于 ActionRedirect)
	RedirectTTL uint32   // 重定向 TTL
	Priority    int      // 优先级
}

