package scan

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/portscan/public"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
)

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000
	packetSendSize = 2500
)

// 表示扫描状态
type State int
const (
	Init State = iota
	Scan
	Done
	Guard
)

// PkgSend 发送的TCP数据包消息
type PkgSend struct {
	ip       string
	port     int
	flag     PkgFlag
	SourceIP string
}

// 表示发送的TCP Flag标识
type PkgFlag int
const (
	SYN PkgFlag = iota
	ACK
)

// PkgResult 包含发送TCP软件包的结果
type PkgResult struct {
	ip   string
	port int
}

type Scanner struct {
	SourceIP           net.IP // 源IP
	listenPort         int // 监听端口
	State            State // 扫描状态
	tcpPacketlistener  net.PacketConn // TCP数据包操作
	TcpPacketSend    chan *PkgSend // 保存要发送的数据包
	tcpChan          chan *PkgResult // 保存返回的数据包
	tcpsequencer     *TCPSequencer // TCP 序列号
	serializeOptions gopacket.SerializeOptions
	ScanResults      *Result // 端口保存结果
	NetworkInterface *net.Interface // 网络接口
	debug            bool // 是否显示扫描过程中的信息
}

// 全局调用
var GScan *Scanner

// 实例化Scan
func NewScanner()error{

	if !public.IsOSSupported(){ // 不是linux系统
		scanner := &Scanner{}
		scanner.ScanResults = NewResult()
		GScan = scanner
		return nil
	}

	rand.Seed(time.Now().UnixNano()) // 设置随机数种子
	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		tcpsequencer: NewTCPSequencer(),
		debug: false,
	}

	rawPort, err := freeport.GetFreePort() // 获取监听端口
	if err != nil {
		return err
	}
	scanner.listenPort = rawPort

	// 启动监听
	tcpConn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketlistener = tcpConn

	scanner.ScanResults = NewResult()
	scanner.tcpChan = make(chan *PkgResult, chanSize)
	scanner.TcpPacketSend = make(chan *PkgSend, packetSendSize)
	err = scanner.TuneSource("8.8.8.8") // 设置源地址
	if err != nil {
		return err
	}
	scanner.StartWorkers() // 启动TCP读写
	GScan = scanner
	return nil
}

// StartWorkers 启动扫描工作所需任务
func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker()
	go s.TCPWriteWorker()
	go s.TCPResultWorker()
}

// TCPReadWorker 读取并解析传入的TCP数据包
func (s *Scanner) TCPReadWorker() {
	defer s.tcpPacketlistener.Close()
	data := make([]byte, 4096)
	for {
		if s.State == Done {
			break
		}

		n, addr, err := s.tcpPacketlistener.ReadFrom(data)
		if err != nil {
			break
		}

		if s.State == Guard {
			continue
		}

		if !strings.Contains(public.GOptions.Hosts, addr.String()) {
			if s.debug{
				logger.LogPortScan.Debugf("[-] 丢弃来自非目标IP的TCP数据包 %s", addr.String())
			}
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// 只考虑传入的数据包
			if tcp.DstPort != layers.TCPPort(s.listenPort) {
				if s.debug{
					logger.LogPortScan.Debugf("[-] 丢弃来自 %s 的TCP数据包 %s:%d 端口不匹配", addr.String(), tcp.DstPort, s.listenPort)
				}
			} else if tcp.SYN && tcp.ACK {
				if s.debug {
					logger.LogPortScan.Debugf("[-] 接受来自 %s:%d 的SYN+ACK数据包", addr.String(), tcp.DstPort)
				}
				s.tcpChan <- &PkgResult{ip: addr.String(), port: int(tcp.SrcPort)}
			}
		}

	}
}

// TCPWriteWorker 发送TCP数据包
func (s *Scanner) TCPWriteWorker() {
	for pkg := range s.TcpPacketSend {
		s.SendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

// SendAsyncPkg 发送消息到目标端口中
func (s *Scanner) SendAsyncPkg(ip string, port int, pkgFlag PkgFlag) {
	ip4 := layers.IPv4{
		SrcIP:    s.SourceIP,
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == SYN {
		tcp.SYN = true
	} else if pkgFlag == ACK {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		if s.debug {
			logger.LogPortScan.Debugf("[-] %s:%d 设置网络层失败: %s", ip, port, err)
		}
	} else {
		err = s.send(ip, s.tcpPacketlistener, &tcp)
		if err != nil {
			if s.debug {
				logger.LogPortScan.Debugf("[-] 发送到 %s:%d 数据包失败:%s", ip, port, err)
			}
		}
	}
}

// send 发送消息
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}

	var (
		retries int
		err     error
	)

send:
	if retries >= maxRetries {
		return err
	}
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// 引入一个小的延迟，以允许网络接口刷新队列
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
}

// TCPResultWorker 处理探针和扫描结果
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		if s.State == Scan {
			//logger.LogPortScan.Debugf("[+] 接收到 %s:%d 响应", ip.ip, ip.port)
			if s.debug{
				logger.LogPortScan.Debugf("[+] 接收到 %s:%d 的回应", ip.ip, ip.port)
			}
			s.ScanResults.AddPort(ip.port) // 添加到result中
		}
	}
}

// EnqueueTCP 传出TCP封包
func (s *Scanner) EnqueueTCP(ip string, port int, pkgtype PkgFlag) {
	s.TcpPacketSend <- &PkgSend{
		ip:   ip,
		port: port,
		flag: pkgtype,
	}
}

// TuneSource 根据IP获取源IP和网络接口
func (s *Scanner) TuneSource(ip string) error {
	var err error
	s.SourceIP, s.NetworkInterface, err = GetSrcParameters(ip)
	if err != nil {
		return err
	}

	return nil
}

// GetSrcParameters 从目标IP获取网络参数
func GetSrcParameters(destIP string) (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, err = GetSourceIP(net.ParseIP(destIP))
	if err != nil {
		return
	}

	networkInterface, err = GetInterfaceFromIP(srcIP)
	if err != nil {
		return
	}

	return
}

// GetSourceIP 获取源IP
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	con, dialUpErr := net.DialUDP("udp", nil, serverAddr)
	if dialUpErr != nil {
		return nil, dialUpErr
	}

	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return nil, nil
}

// GetInterfaceFromIP 从本地IP地址获取网络接口的名称
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("找不到该 %s 网络接口 %s", address)
}

// ConnectPort 使用Connect方式扫描端口
func ConnectPort(host string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, err
}