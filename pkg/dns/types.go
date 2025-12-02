package dns

import "net"

// DNS 查询类型常量
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeANY   uint16 = 255
)

// TypeName 返回 DNS 类型名称
func TypeName(qtype uint16) string {
	switch qtype {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeANY:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}

// DNS 类常量
const (
	ClassIN uint16 = 1
)

// DNS 响应码
const (
	RCodeNoError        uint16 = 0
	RCodeFormatError    uint16 = 1
	RCodeServerFailure  uint16 = 2
	RCodeNXDomain       uint16 = 3
	RCodeNotImplemented uint16 = 4
	RCodeRefused        uint16 = 5
)

// Header DNS 消息头部
type Header struct {
	ID      uint16 // 事务 ID
	Flags   uint16 // 标志位
	QDCount uint16 // 问题数
	ANCount uint16 // 回答数
	NSCount uint16 // 授权数
	ARCount uint16 // 附加数
}

// Question DNS 问题部分
type Question struct {
	Name   string // 域名
	QType  uint16 // 查询类型
	QClass uint16 // 查询类
}

// ResourceRecord DNS 资源记录
type ResourceRecord struct {
	Name     string // 域名
	Type     uint16 // 记录类型
	Class    uint16 // 记录类
	TTL      uint32 // 生存时间
	RDLength uint16 // 资源数据长度
	RData    []byte // 资源数据
}

// Message DNS 消息
type Message struct {
	Header     Header           // 头部
	Questions  []Question       // 问题部分
	Answers    []ResourceRecord // 回答部分
	Authority  []ResourceRecord // 授权部分
	Additional []ResourceRecord // 附加部分
	RawData    []byte           // 原始数据
}

// IsQuery 判断是否为查询消息
func (m *Message) IsQuery() bool {
	return (m.Header.Flags & 0x8000) == 0
}

// IsResponse 判断是否为响应消息
func (m *Message) IsResponse() bool {
	return (m.Header.Flags & 0x8000) != 0
}

// GetRCode 获取响应码
func (m *Message) GetRCode() uint16 {
	return m.Header.Flags & 0x000F
}

// GetOpCode 获取操作码
func (m *Message) GetOpCode() uint16 {
	return (m.Header.Flags >> 11) & 0x0F
}

// GetQueryName 获取第一个查询的域名
func (m *Message) GetQueryName() string {
	if len(m.Questions) > 0 {
		return m.Questions[0].Name
	}
	return ""
}

// GetQueryType 获取第一个查询的类型
func (m *Message) GetQueryType() uint16 {
	if len(m.Questions) > 0 {
		return m.Questions[0].QType
	}
	return 0
}

// BuildNXDomainResponse 构建 NXDOMAIN 响应
func BuildNXDomainResponse(query *Message) []byte {
	if query == nil || len(query.RawData) < 12 {
		return nil
	}

	response := make([]byte, 12)
	copy(response, query.RawData[:12])

	// 设置响应标志: QR=1, RCODE=3 (NXDOMAIN)
	flags := uint16(0x8000) | (query.Header.Flags & 0x0100) | RCodeNXDomain
	response[2] = byte(flags >> 8)
	response[3] = byte(flags)

	// 设置回答数为 0
	response[6] = 0
	response[7] = 0

	// 添加问题部分
	if len(query.RawData) > 12 {
		response = append(response, query.RawData[12:]...)
	}

	return response
}

// BuildAResponse 构建 A 记录响应
func BuildAResponse(query *Message, ip net.IP, ttl uint32) []byte {
	if query == nil || len(query.RawData) < 12 || ip == nil {
		return nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil
	}

	response := make([]byte, len(query.RawData))
	copy(response, query.RawData)

	// 设置响应标志: QR=1, AA=1, RD=query.RD, RCODE=0
	flags := uint16(0x8400) | (query.Header.Flags & 0x0100)
	response[2] = byte(flags >> 8)
	response[3] = byte(flags)

	// 设置回答数为 1
	response[6] = 0
	response[7] = 1

	// 添加答案记录 (压缩指针指向问题中的域名)
	// 格式: 压缩指针(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(4)
	answer := []byte{
		0xC0, 0x0C, // 压缩指针指向偏移 12 (问题部分的域名)
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl), // TTL
		0x00, 0x04, // RDLENGTH = 4
		ipv4[0], ipv4[1], ipv4[2], ipv4[3], // IP 地址
	}

	return append(response, answer...)
}

// BuildAAAAResponse 构建 AAAA 记录响应
func BuildAAAAResponse(query *Message, ip net.IP, ttl uint32) []byte {
	if query == nil || len(query.RawData) < 12 || ip == nil {
		return nil
	}

	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil
	}

	response := make([]byte, len(query.RawData))
	copy(response, query.RawData)

	// 设置响应标志
	flags := uint16(0x8400) | (query.Header.Flags & 0x0100)
	response[2] = byte(flags >> 8)
	response[3] = byte(flags)

	// 设置回答数为 1
	response[6] = 0
	response[7] = 1

	// 添加答案记录
	answer := []byte{
		0xC0, 0x0C, // 压缩指针
		0x00, 0x1C, // TYPE = AAAA
		0x00, 0x01, // CLASS = IN
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl), // TTL
		0x00, 0x10, // RDLENGTH = 16
	}
	answer = append(answer, ipv6...)

	return append(response, answer...)
}
