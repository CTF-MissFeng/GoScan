package subdomain

import (
	"bytes"
	"encoding/gob"
	"os"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/domain"
	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/dnsprobe"
	"github.com/CTF-MissFeng/GoScan/Client/util/conf"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Client/util/nsq"
	"github.com/CTF-MissFeng/GoScan/Client/util/nsq/Production"

	"github.com/gogf/gf/text/gstr"
	"github.com/nsqio/go-nsq"
)

// 子域名扫描 消费者类型
type Handler struct {
	Title string
}

// 子域名扫描 初始化消费者
func InitConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 59*time.Minute // 消息反馈超时时间
	config.HeartbeatInterval = 20*time.Second // 心跳时间
	//config.MsgTimeout = time.Duration(int64(conf.Gconf.Domain.NsqTimeout)) * time.Second // 设置消息反馈超时时间
	if err := config.Validate(); err != nil{
		logger.LogDomain.Fatalf("[-] [消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.LogDomain.Fatalf("[-] [消费者] 创建消费者任务队列失败:%s", err.Error())
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "subDomain"
	}
	client := &Handler{
		Title: hostname,
	}
	consumer.AddHandler(client)
	host := conf.Gconf.Nsq.NsqHost
	err1 := consumer.ConnectToNSQD(host) // 连接到nsqd
	if err1 != nil{
		logger.LogDomain.Fatalf("[-] [消费者] 连接任务队列服务器失败:%s", err1.Error())
	}else{
		logger.LogDomain.Infof("[+] [消费者] 连接任务队列服务器成功")
	}
}

// 投递子域名扫描消息格式
type NsqPushDomain struct{
	CusName string // 厂商名
	Domain string // 主域名
}

// 子域名扫描 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil
	}
	var DomainInfo NsqPushDomain
	dec := gob.NewDecoder(bytes.NewReader(msg.Body))
	err := dec.Decode(&DomainInfo)
	if err != nil{
		logger.LogDomain.Warningf("[-] 消息解码失败:%s", err.Error())
		return err
	}
	go nsqTouch(msg)
	results,err := domain.GetSubdomain(DomainInfo.Domain) // 执行子域名探测任务
	if err != nil{
		logger.LogDomain.Warningf("[-] Domain：[%s] 子域名探测失败:%s", DomainInfo.Domain, err.Error())
		return err
	}
	if results == nil{
		logger.LogDomain.Warningf("[-] Domain：[%s] 未发现子域名", DomainInfo.Domain)
		return SendMessageFail(DomainInfo)
	}
	return SendMessage(results, DomainInfo)
}

func nsqTouch(msg *nsq.Message){
	for{
		if msg.HasResponded(){
			break
		}
		time.Sleep(50*time.Second)
		msg.Touch()
	}
}

// 成功后将结果投递到消息队列
func SendMessage(r []*dnsprobe.ResSubdomain,n NsqPushDomain)error{
	SendData := make([]*Gnsq.ResponseSubDomainStruct, 0)
	for _, v := range r{
		SendData = append(SendData, &Gnsq.ResponseSubDomainStruct{
			CusName: n.CusName,
			Domain: n.Domain,
			Subdomain:v.SubDomain,
			Ip: v.IP[0],
			Cname: gstr.Join(v.CNAME, ","),
			Cdn: v.Cdn,
		})
	}
	if len(SendData) > 100{ // 防止一次性投递消息过大
		SendDatatmp := make([]*Gnsq.ResponseSubDomainStruct, 0)
		index := 0
		for _,v := range SendData{
			index ++
			SendDatatmp = append(SendDatatmp, v)
			if index >= 100{
				err := Production.SendTopicMessages(Gnsq.RSubDomainTopic, SendDatatmp)
				if err != nil{
					logger.LogPortScan.Warningf("[-] 投递消息失败:%s", err.Error())
					return err
				}
				time.Sleep(time.Second*1)
				index = 0
				SendDatatmp = make([]*Gnsq.ResponseSubDomainStruct, 0)
			}
		}
		if len(SendDatatmp) != 0{
			err := Production.SendTopicMessages(Gnsq.RSubDomainTopic, SendDatatmp)
			if err != nil{
				logger.LogPortScan.Warningf("[-] 投递消息失败:%s", err.Error())
				return err
			}
		}
		return nil
	}
	err := Production.SendTopicMessages(Gnsq.RSubDomainTopic, SendData)
	if err != nil{
		logger.LogPortScan.Warningf("[-] 投递消息失败:%s", err.Error())
	}
	return nil
}

// 失败后将结果投递到消息队列
func SendMessageFail(n NsqPushDomain)error{
	SendData := []*Gnsq.ResponseSubDomainStruct{{
		CusName:   n.CusName,
		Domain:    n.Domain,
		Subdomain: "null",
		}}
	err := Production.SendTopicMessages(Gnsq.RSubDomainTopic, SendData)
	if err != nil{
		logger.LogPortScan.Warningf("[-] 投递消息失败:%s", err.Error())
		return err
	}
	return nil
}