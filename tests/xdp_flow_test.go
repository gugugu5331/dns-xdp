// XDP 完整流程测试
// 验证: XDP 程序 → AF_XDP Socket → DNS 解析

package tests

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"xdp-dns/pkg/dns"
	"xdp-dns/xdp"

	"github.com/vishvananda/netlink"
)

// 检查是否有 root 权限
func checkRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("跳过测试: 需要 root 权限来运行 XDP 程序")
	}
}

// 获取可用的网络接口
func getTestInterface(t *testing.T) (string, int) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("获取网络接口失败: %v", err)
	}

	// 优先选择 loopback
	for _, link := range links {
		if link.Attrs().Name == "lo" {
			return "lo", link.Attrs().Index
		}
	}

	// 选择第一个 up 状态的非 loopback 接口
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.OperState == netlink.OperUp && attrs.Name != "lo" {
			return attrs.Name, attrs.Index
		}
	}

	t.Skip("没有可用的网络接口")
	return "", 0
}

// TestXDPProgramLoad 测试 XDP 程序加载
func TestXDPProgramLoad(t *testing.T) {
	checkRoot(t)
	ifname, ifindex := getTestInterface(t)
	t.Logf("使用接口: %s (index: %d)", ifname, ifindex)

	// 创建简单的 XDP 程序
	program, err := xdp.NewProgram(1)
	if err != nil {
		t.Fatalf("创建 XDP 程序失败: %v", err)
	}
	defer program.Close()

	// 附加到网络接口
	if err := program.Attach(ifindex); err != nil {
		t.Fatalf("附加 XDP 程序失败: %v", err)
	}
	defer program.Detach(ifindex)

	t.Log("✓ XDP 程序加载成功")
}

// TestAFXDPSocket 测试 AF_XDP Socket 创建
func TestAFXDPSocket(t *testing.T) {
	checkRoot(t)
	ifname, ifindex := getTestInterface(t)
	t.Logf("使用接口: %s (index: %d)", ifname, ifindex)

	// 设置 RLIMIT_MEMLOCK
	cmd := exec.Command("sh", "-c", "ulimit -l unlimited")
	cmd.Run()

	// 创建 XDP 程序
	program, err := xdp.NewProgram(1)
	if err != nil {
		t.Fatalf("创建 XDP 程序失败: %v", err)
	}
	defer program.Close()

	if err := program.Attach(ifindex); err != nil {
		t.Fatalf("附加 XDP 程序失败: %v", err)
	}
	defer program.Detach(ifindex)

	// 创建 AF_XDP Socket
	opts := &xdp.SocketOptions{
		NumFrames:              128,
		FrameSize:              2048,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	}

	xsk, err := xdp.NewSocket(ifindex, 0, opts)
	if err != nil {
		t.Fatalf("创建 AF_XDP Socket 失败: %v", err)
	}
	defer xsk.Close()

	// 注册 Socket
	if err := program.Register(0, xsk.FD()); err != nil {
		t.Fatalf("注册 Socket 失败: %v", err)
	}

	t.Log("✓ AF_XDP Socket 创建成功")
	t.Logf("  Socket FD: %d", xsk.FD())
	t.Logf("  Frame Size: %d", opts.FrameSize)
	t.Logf("  Num Frames: %d", opts.NumFrames)
}

// TestDNSPacketParsing 测试 DNS 包解析
func TestDNSPacketParsing(t *testing.T) {
	// 构造一个完整的 DNS 查询包 (包含 ETH + IP + UDP + DNS)
	dnsPayload := buildDNSQuery("www.example.com")

	parser := dns.NewParser()
	msg, err := parser.Parse(dnsPayload)
	if err != nil {
		t.Fatalf("DNS 解析失败: %v", err)
	}

	t.Logf("✓ DNS 解析成功")
	t.Logf("  ID: 0x%04x", msg.Header.ID)
	t.Logf("  域名: %s", msg.GetQueryDomain())
	t.Logf("  类型: %d", msg.GetQueryType())
}

// 构建 DNS 查询包
func buildDNSQuery(domain string) []byte {
	packet := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Other counts
	}
	// 域名编码
	for _, part := range strings.Split(domain, ".") {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00)       // 结束
	packet = append(packet, 0x00, 0x01) // Type A
	packet = append(packet, 0x00, 0x01) // Class IN
	return packet
}
