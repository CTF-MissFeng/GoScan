package Production

import (
	"Client/util/conf"
	"Client/util/logger"
	"time"

	"github.com/nsqio/go-nsq"
)

// 全局变量，其他模块调用生产者
var NsqProducer *nsq.Producer

// 初始化Nsq生产者
func NsqInitProducer(){
	config := nsq.NewConfig()
	addres := conf.Gconf.Nsq.CNsqHost
	producer, err := nsq.NewProducer(addres, config)
	if err != nil {
		logger.Log.Fatalf("[-] [生产者] 连接到消息队列服务器失败:%s", err.Error())
	}
	err = producer.Ping()
	if err != nil {
		logger.Log.Fatalf("[-] [生产者] 连接到消息队列服务器失败:%s", err.Error())
	}
	logger.Log.Debug("[+] [生产者] Client连接到消息队列服务器成功")
	NsqProducer = producer
}

// 往topic中投递消息
func SendTopicMessages(topicName string, msg []byte){
	if err := NsqProducer.Ping(); err != nil{
		headerNsq()
	}

	err := NsqProducer.Publish(topicName, msg)
	if err != nil{
		logger.Log.Warningf("[-] [生产者] topic:%s 投递消息失败:%s", topicName, err.Error())
	}
}

// 防止nsq掉线，重新连接
func headerNsq(){
	for {
		config := nsq.NewConfig()
		addres := conf.Gconf.Nsq.CNsqHost
		producer, err := nsq.NewProducer(addres, config)
		if err != nil {
			logger.Log.Warningf("[-] [生产者] 重新连接到消息队列服务器失败:%s", err.Error())
			time.Sleep(5*time.Second)
			continue
		}
		err = producer.Ping()
		if err != nil {
			time.Sleep(5*time.Second)
			logger.Log.Warningf("[-] [生产者] 连接到消息队列服务器失败:%s", err.Error())
			continue
		}
		logger.Log.Debug("[+] [生产者] Client重新连接到消息队列服务器成功")
		NsqProducer = producer
		break
	}
}