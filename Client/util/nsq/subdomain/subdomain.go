package subdomain

import (
	"bytes"
	"encoding/gob"
	"os"
	"time"

	"Client/plug/domain"
	"Client/plug/domain/dnsprobe"
	"Client/util/conf"
	"Client/util/logger"
	Gnsq "Client/util/nsq"
	"Client/util/nsq/Production"

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
	config.MsgTimeout = time.Duration(int64(conf.Gconf.Domain.NsqTimeout)) * time.Second // 设置消息反馈超时时间
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
	results,err := domain.GetSubdomain(DomainInfo.Domain) // 执行子域名探测任务
	if err != nil{
		logger.LogDomain.Warningf("[-] Domain：[%s] 子域名探测失败:%s", DomainInfo.Domain, err.Error())
		return err
	}
	if results == nil{
		logger.LogDomain.Warningf("[-] Domain：[%s] 未发现子域名", DomainInfo.Domain)
		if err = SendMessageFail(DomainInfo); err != nil{
			return err
		}
		return nil
	}
	if err = SendMessage(results, DomainInfo); err != nil{
		return err
	}
	return nil
}

// 返回结果格式
type SendMessageStruct struct{
	CusName string
	Domain string
	Subdomain string
	Ip string
	Cname string
	Cdn bool
	Location string
	Flag bool
	NsqFlag bool
}

// 成功后将结果投递到消息队列
func SendMessage(r []*dnsprobe.ResSubdomain,n NsqPushDomain)error{
	SendData := make([]*SendMessageStruct, 0)
	for _, v := range r{
		SendData = append(SendData, &SendMessageStruct{
			CusName: n.CusName,
			Domain: n.Domain,
			Subdomain:v.SubDomain,
			Ip: v.IP[0],
			Cname: gstr.Join(v.CNAME, ","),
			Cdn: v.Cdn,
		})
	}
	network := bytes.Buffer{}
	enc := gob.NewEncoder(&network)
	err := enc.Encode(&SendData)
	if err != nil {
		logger.LogDomain.Warningf("[-] 投递消息编码失败:%s", err.Error())
		return err
	}
	Production.SendTopicMessages(Gnsq.RSubDomainTopic, network.Bytes())
	return nil
}

// 失败后将结果投递到消息队列
func SendMessageFail(n NsqPushDomain)error{
	SendData := []*SendMessageStruct{{
		CusName:   n.CusName,
		Domain:    n.Domain,
		Subdomain: "null",
		}}
	network := bytes.Buffer{}
	enc := gob.NewEncoder(&network)
	err := enc.Encode(&SendData)
	if err != nil {
		logger.LogDomain.Warningf("[-] 投递消息编码失败:%s", err.Error())
		return err
	}
	Production.SendTopicMessages(Gnsq.RSubDomainTopic, network.Bytes())
	return nil
}