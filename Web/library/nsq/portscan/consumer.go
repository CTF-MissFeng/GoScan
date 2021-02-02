package portscan

import (
	"bytes"
	"encoding/gob"
	"strings"
	"time"

	"Web/app/dao"
	"Web/library/logger"

	"github.com/gogf/gf/frame/g"
	"github.com/nsqio/go-nsq"
)

// 端口扫描 消费者类型
type PortScanHandler struct {
	Title string
}

// 端口扫描 初始化消费者
func InitConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 100 * time.Second // 设置消息反馈超时时间
	if err := config.Validate(); err != nil{
		logger.WebLog.Fatalf("[-] [端口扫描消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.WebLog.Fatalf("[-] [端口扫描消费者] 创建消费者消息队列失败:%s", err.Error())
	} else{
		client := &PortScanHandler{
			Title: "server",
		}
		consumer.AddHandler(client)
		err1 := consumer.ConnectToNSQD(g.Cfg().GetString("nsq.CTcpHost")) // 连接到nsqd
		if err1 != nil{
			logger.WebLog.Fatalf("[-] [端口扫描消费者] 连接消息队列服务失败:%s", err1.Error())
		}else{
			logger.WebLog.Infof("[+] [端口扫描消费者] 连接消息队列服务成功")
		}
	}
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

// 端口扫描 接受nsqd消息
func (m *PortScanHandler) HandleMessage(msg *nsq.Message)error{
	if len(msg.Body) == 0 {
		return nil //返回nil会自动将FIN命令发送到NSQ，以将消息标记为已处理
	}
	var result []SendMessageStruct
	dec := gob.NewDecoder(bytes.NewReader(msg.Body))
	err := dec.Decode(&result)
	if err != nil{
		logger.WebLog.Warningf("[-] [端口扫描消费者] 解码消息失败:%s", err.Error())
		return nil
	}
	if len(result) == 0{
		return nil
	}
	if strings.Contains(result[0].CusName, "util-"){
		if err := utilPortScanPush(result); err != nil{
			return err
		}
	}else{
		if err := portScanPush(result); err != nil{
			return err
		}
	}
	return nil
}

// portScanPush 处理端口扫描结果
func portScanPush(r []SendMessageStruct)error{
	_,err := dao.ScanSubdomain.Where("ip=?", r[0].Host).Update(g.Map{"flag":true}) // 更改子域名扫描状态
	if err != nil {
		logger.WebLog.Warningf("[-] [端口扫描] 更改子域名扫描状态失败:%s", err.Error())
		return err
	}
	if len(r) == 1{ // 处理没有结果的
		if r[0].ServiceName == "null"{
			return nil
		}
	}
	if _,err = dao.ScanPort.Insert(r); err != nil{ // 批量插入
		logger.WebLog.Warningf("[-] [端口扫描] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}

// utilPortScanPush 处理端口扫描结果
func utilPortScanPush(r []SendMessageStruct)error{
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-","",-1)
	res,err := dao.UtilPortscanTask.Where("cus_name=?",CusName).FindOne()
	if err != nil || res == nil{
		logger.WebLog.Warningf("[-] [Util-端口扫描扫描消费者] 数据库查询对应任务名失败：%s", err.Error())
		return nil
	}
	if _,err = dao.UtilPortscanTask.Update(g.Map{"scan_num":res.ScanNum+1}, "cus_name", CusName);err != nil{
		logger.WebLog.Warningf("[-] [Util-端口扫描扫描消费者] 修改已扫描数失败:%s", err.Error())
	}
	if len(r) == 1{ // 处理没有结果的
		if r[0].ServiceName == "null"{
			return nil
		}
	}
	for i,_ := range r{
		r[i].CusName = CusName
	}
	if _,err = dao.UtilPortscanResult.Insert(r); err != nil{ // 批量插入
		logger.WebLog.Warningf("[-] [Util-端口扫描扫描消费者] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}