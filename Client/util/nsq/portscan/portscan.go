package portscan

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"time"

	"Client/plug/portscan/probe"
	"Client/plug/portscan/public"
	"Client/plug/portscan/runner"
	"Client/util/conf"
	"Client/util/logger"
	Gnsq "Client/util/nsq"
	"Client/util/nsq/Production"

	"github.com/nsqio/go-nsq"
)

// 端口扫描 消费者类型
type Handler struct {
	Title string
}

// 初始化端口扫描
func Init(){
	public.GOptions = &public.Options{}
	public.GOptions.Hosts = "1.1.1.1"
	runner.Init() // 初始化端口扫描
	probe.NewNmap() // 初始化nmap
	initConsumer(Gnsq.PortScanTopic,Gnsq.PortScanTopicChanl) // 初始化端口扫描接受队列
}

// 端口扫描 初始化消费者
func initConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = time.Duration(int64(conf.Gconf.PortScan.NsqTimeout)) * time.Second // 设置消息反馈超时时间
	if err := config.Validate(); err != nil{
		logger.LogDomain.Fatalf("[-] [消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.LogPortScan.Fatalf("[-] 创建消费者任务队列实例失败:%s", err.Error())
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "PortScan"
	}
	client := &Handler{
		Title: hostname,
	}
	consumer.AddHandler(client)

	host := conf.Gconf.Nsq.NsqHost
	err1 := consumer.ConnectToNSQD(host) // 连接到nsqd
	if err1 != nil{
		logger.LogPortScan.Fatalf("[-] [消费者] 连接任务队列服务器失败:%s", err1.Error())
	}else{
		logger.LogPortScan.Infof("[+] [消费者] 连接任务队列服务器成功")
		go header(consumer)
	}
}

// 维持消费者心跳
func header(c *nsq.Consumer){
	for {
		c.Stats()
		time.Sleep(10*time.Second)
	}
}

// 端口扫描 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil //返回nil会自动将FIN命令发送到NSQ，以将消息标记为已处理
	}
	var portsInfo public.Options
	dec := gob.NewDecoder(bytes.NewReader(msg.Body))
	err := dec.Decode(&portsInfo)
	if err != nil{
		logger.LogPortScan.Warningf("[-] 解码消息失败:%s", err.Error())
		return nil
	}

	if !strings.Contains(portsInfo.CusName,"util"){
		portsInfo.Verify = conf.Gconf.PortScan.Verify
		portsInfo.Ping = conf.Gconf.PortScan.Ping
		portsInfo.Retries = conf.Gconf.PortScan.Retries
		portsInfo.Rate = conf.Gconf.PortScan.Rate
		portsInfo.Timeout = conf.Gconf.PortScan.Timeout
		portsInfo.Ports = conf.Gconf.PortScan.Ports
		portsInfo.NmapTimeout = conf.Gconf.PortScan.NsqTimeout
		portsInfo.WafNum = conf.Gconf.PortScan.WafNum
		portsInfo.Detection = conf.Gconf.PortScan.Detection
	}

	public.GOptions = &portsInfo // 赋值给全局变量调用
	tmpPorts := portsInfo.Ports
	if public.GOptions.Detection == "null"{ // 不进行优先扫描
		err = runner.Run()
		if err != nil{
			logger.LogPortScan.Warningf("[-] %s %s", public.GOptions.Hosts, err.Error())
			return err // 返回错误则消息重新排队
		}
		number, results := runner.Output()
		if number != 0{
			SendMessage(results) // 投递消息结果
		}else{
			SendMessageFail(portsInfo.Hosts, portsInfo.Ports) // 投递无结果的消息
		}
		return nil
	}

	// 进行优先扫描
	public.GOptions.Ports = public.GOptions.Detection
	err = runner.Run()
	if err != nil{
		logger.LogPortScan.Warningf("[-] %s %s",public.GOptions.Hosts, err.Error())
		return err
	}
	number,_ := runner.Output()
	if number < 1{
		logger.LogPortScan.Debugf("[+] %s 优先扫描 未发现存活端口", public.GOptions.Hosts)
		SendMessageFail(portsInfo.Hosts, portsInfo.Ports) // 投递无结果的消息
		return nil
	}
	logger.LogPortScan.Debugf("[+] 优先扫描 %s 发现%d个端口存活", public.GOptions.Hosts, number)
	public.GOptions.Ports = tmpPorts
	public.GOptions.Detection = "null" // 还原优先扫描
	err = runner.Run()
	if err != nil{
		logger.LogPortScan.Warningf("端口扫描 %s %s",public.GOptions.Hosts, err.Error())
		return err
	}
	number, results := runner.Output()
	if number != 0{
		SendMessage(results) // 投递消息结果
	}else{
		SendMessageFail(portsInfo.Hosts, portsInfo.Ports) // 投递无结果的消息
	}

	return nil
}

// 存储端口扫描结果表
type SendMessageStruct struct{
	CusName string
	Host string
	Port string
	ServiceName string
	VendorProduct string
	Version string
	HttpFlag bool
	Url string
	Code int
	Title string
	Flag bool
	NsqFlag bool
}

// 将扫描结果投递到消息队列
func SendMessage(data []*probe.Task){
	SendData := make([]*SendMessageStruct, 0) // 保存组装消息
	for _, task := range data{
		host,port,err := getAddress(task.Addr)
		if err != nil{
			logger.LogPortScan.Warningf("[-] 投递消息 解析Address错误：%s", task.Addr)
			continue
		}

		httpflag := false
		if len(task.Url) == 0{
			httpflag = false
		}else{
			httpflag = true
		}
		SendData = append(SendData, &SendMessageStruct{
			CusName: public.GOptions.CusName,
			Host: host,
			Port: port,
			ServiceName: task.ServiceNmae,
			VendorProduct: task.VendorProduct,
			Version:  task.Version,
			HttpFlag: httpflag,
			Url: task.Url,
			Title: task.Title,
			Code: task.StatusCode,
			Flag: false,
			NsqFlag: false,
		})
	}
	network := bytes.Buffer{}
	enc := gob.NewEncoder(&network)
	err := enc.Encode(&SendData)
	if err != nil {
		logger.LogPortScan.Warningf("[-] 投递消息编码失败:%s", err.Error())
		return
	}
	Production.SendTopicMessages(Gnsq.RPortScanTopic, network.Bytes())
}

// 解析address得到host和ip
func getAddress(s string)(string, string, error){
	strlist := strings.Split(s,":")
	if len(strlist) != 2{
		return "", "", fmt.Errorf("Address格式错误:%s", s)
	}
	return strlist[0], strlist[1], nil
}

// 投递扫描失败或没有的结果,以便web端显示进度
func SendMessageFail(host, port string){
	result :=  SendMessageStruct{
		CusName: public.GOptions.CusName,
		Host: host,
		Port: port,
		ServiceName:"null",
		Flag: false,
		NsqFlag: false,
	}
	SendData := make([]SendMessageStruct, 0) // 保存组装消息
	SendData = append(SendData, result)
	network := bytes.Buffer{}
	enc := gob.NewEncoder(&network)
	err := enc.Encode(&SendData)
	if err != nil {
		logger.LogPortScan.Warningf("[-] 投递消息编码失败:%s", err.Error())
		return
	}
	Production.SendTopicMessages(Gnsq.RPortScanTopic, network.Bytes())
}