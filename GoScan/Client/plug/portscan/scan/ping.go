package scan

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	DeadlineSec  = 5 // 读取超时时间
	ProtocolICMP = 1
)

// PingHost 使用ICMP探测指定主机是否存活
func PingHost(address string) error {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0") // 侦听ICMP数据包
	if err != nil {
		return fmt.Errorf("[ping探测] %s 侦听ICMP失败:%s", address, err.Error())
	}

	defer func() {
		if c != nil{
			c.Close()
		}
	}()

	dst, err := net.ResolveIPAddr("ip4", address) // 解析域名或IP地址
	if err != nil {
		return fmt.Errorf("[ping探测] %s ip地址格式错误：%s", address, err.Error())
	}

	m := icmp.Message{ // 组装ICMP消息
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}
	data, err := m.Marshal(nil) // 编码ICMP消息
	if err != nil {
		return fmt.Errorf("[ping探测] %s ICMP消息编码失败：%s",address, err.Error())
	}

	_, err = c.WriteTo(data, dst) // 发送ICMP消息
	if err != nil {
		return fmt.Errorf("[ping探测] %s ICMP发送消息失败：%s", address, err.Error())
	}

	reply := make([]byte, 1500) // 设置缓冲区大小
	err = c.SetReadDeadline(time.Now().Add(DeadlineSec * time.Second)) // 设置读取超时时间
	if err != nil {
		return fmt.Errorf("[ping探测] %s ICMP设置超时读取失败：%s", address, err.Error())
	}

	n, _, err := c.ReadFrom(reply) // 从连接中读取ICMP消息
	if err != nil {
		return fmt.Errorf("[ping探测] %s ICMP消息读取失败：%s", address, err.Error())
	}

	rm, err := icmp.ParseMessage(ProtocolICMP, reply[:n]) // 解析ICMP消息
	if err != nil {
		return fmt.Errorf("[ping探测] %s ICMP消息读取解析失败：%s", address, err.Error())
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return nil // 主机存活
	default:
		return fmt.Errorf("[ping探测] %s 主机不存活", address)
	}
}