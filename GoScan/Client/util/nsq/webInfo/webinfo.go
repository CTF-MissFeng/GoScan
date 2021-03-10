package webInfo

import (
	"bytes"
	"encoding/gob"
	"os"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/web"
	"github.com/CTF-MissFeng/GoScan/Client/util/conf"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Client/util/nsq"
	"github.com/CTF-MissFeng/GoScan/Client/util/nsq/Production"

	"github.com/nsqio/go-nsq"
)

// web探测扫描 消费者类型
type Handler struct {
	Title string
}

// web探测 初始化消费者
func InitConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 59*time.Minute // 消息反馈超时时间
	config.HeartbeatInterval = 20*time.Second // 心跳时间
	//config.MsgTimeout = time.Duration(int64(conf.Gconf.Domain.NsqTimeout)) * time.Second // 设置消息反馈超时时间
	if err := config.Validate(); err != nil{
		logger.LogWebInfo.Fatalf("[-] [消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.LogWebInfo.Fatalf("[-] [消费者] 创建消费者任务队列失败:%s", err.Error())
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "webinfo"
	}
	client := &Handler{
		Title: hostname,
	}
	consumer.AddHandler(client)
	host := conf.Gconf.Nsq.NsqHost
	err1 := consumer.ConnectToNSQD(host) // 连接到nsqd
	if err1 != nil{
		logger.LogWebInfo.Fatalf("[-] [消费者] 连接任务队列服务器失败:%s", err1.Error())
	}else{
		logger.LogWebInfo.Infof("[+] [消费者] 连接任务队列服务器成功")
	}
}

// 投递web扫描消息格式
type NsqPushWeb struct{
	CusName string
	SubDomain []string
	ServiceName string
	Port int
	Ip string
}

// 返回结果格式
type SendMessageStruct struct{
	CusName string `json:"cus_name"`
	Host string `json:"host"`
	Data []*web.ResultWebInfo `json:"data"`
}

// web探测 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil
	}
	var WebInfoInfo NsqPushWeb
	dec := gob.NewDecoder(bytes.NewReader(msg.Body))
	err := dec.Decode(&WebInfoInfo)
	if err != nil{
		logger.LogWebInfo.Warningf("[-] 消息解码失败:%s", err.Error())
		return err
	}
	go nsqTouch(msg)
	apps := web.Detection{
		SubDomain: WebInfoInfo.SubDomain,
		ServiceName: WebInfoInfo.ServiceName,
		Port: WebInfoInfo.Port,
	}
	results := apps.GetWebInfo()
	if len(results) == 0{
		logger.LogWebInfo.Warningf("[-] web探测结果为空:%s:%d", WebInfoInfo.SubDomain, WebInfoInfo.Port)
		return nil
	}
	pubMsg := SendMessageStruct{}
	pubMsg.CusName = WebInfoInfo.CusName
	pubMsg.Host = WebInfoInfo.Ip
	pubMsg.Data = results
	return SendMessage(WebInfoInfo.CusName,WebInfoInfo.Ip, pubMsg)
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
func SendMessage(cusName string, host string, r SendMessageStruct)error{
	if len(r.Data) > 10{ // 防止一次性投递消息过大
		SendData := SendMessageStruct{}
		SendData.CusName = cusName
		SendData.Host = host
		SendDatatmp := make([]*web.ResultWebInfo, 0)
		index := 0
		for _,v := range r.Data{
			index ++
			SendDatatmp = append(SendDatatmp, v)
			if index >= 10{
				SendData.Data = SendDatatmp
				if err := Production.SendTopicMessages(Gnsq.RWebInfoTopic, SendData); err != nil{
					logger.LogDomain.Warningf("[-] 投递消息失败:%s", err.Error())
					return err
				}
				time.Sleep(1*time.Second) // 延迟1秒
				index = 0
				SendDatatmp = make([]*web.ResultWebInfo, 0)
			}
		}
		if len(SendDatatmp) != 0{
			if err := Production.SendTopicMessages(Gnsq.RWebInfoTopic, SendData); err != nil{
				logger.LogDomain.Warningf("[-] 投递消息失败:%s", err.Error())
				return err
			}
		}
		return nil
	}else{
		err := Production.SendTopicMessages(Gnsq.RWebInfoTopic, r)
		if err != nil{
			logger.LogDomain.Warningf("[-] 投递消息失败:%s", err.Error())
			return err
		}
		return nil
	}
}