package portscan

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/dao"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Web/library/nsq"

	"github.com/gogf/gf/encoding/gbase64"
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
	config.MsgTimeout = 10 * time.Minute
	if err := config.Validate(); err != nil{
		logger.WebLog.Fatalf("[-] [端口扫描消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil && consumer == nil{
		logger.WebLog.Fatalf("[-] [端口扫描消费者] 创建消费者消息队列失败:%s", err.Error())
	}
	client := &PortScanHandler{
		Title: "server",
	}
	consumer.AddHandler(client)
	if err1 := consumer.ConnectToNSQD(g.Cfg().GetString("nsq.TcpHost")); err1 != nil{
		logger.WebLog.Fatalf("[-] [端口扫描消费者] 连接消息队列服务失败:%s", err1.Error())
	}
	logger.WebLog.Infof("[+] [端口扫描消费者] 连接消息队列服务成功")
}

// 端口扫描 接受nsqd消息
func (m *PortScanHandler) HandleMessage(msg *nsq.Message)error{
	if len(msg.Body) == 0 {
		return nil
	}
	var result []Gnsq.ResponsePortScanStruct
	msgStr, err := gbase64.Decode(msg.Body)
	if err != nil{
		logger.WebLog.Warningf("[-] [端口扫描消费者] Base64解码消息失败:%s", err.Error())
		return nil
	}
	if err = json.Unmarshal(msgStr,&result); err != nil{
		logger.WebLog.Warningf("[-] [端口扫描消费者] Json反序列化失败:%s", err.Error())
		return nil
	}
	if len(result) == 0{
		logger.WebLog.Warningf("[-] [端口扫描消费者] 解码后无数据")
		return nil
	}
	if strings.Contains(result[0].CusName, "util-"){
		return utilPortScanPush(result)
	}
	return portScanPush(result)
}

// portScanPush 处理端口扫描结果
func portScanPush(r []Gnsq.ResponsePortScanStruct)error{
	time.Sleep(1*time.Second)
	count,err := dao.ScanPort.Where("host=?", r[0].Host).Count()
	if err != nil {
		logger.WebLog.Warningf("[-] [端口扫描] 查询Host数据库错误:%s", err.Error())
		return err
	}
	if count != 0{
		logger.WebLog.Warningf("[-] [端口扫描] [%s] 发现重复Host", r[0].Host)
		return nil
	}
	_,err = dao.ScanSubdomain.Where("ip=?", r[0].Host).Update(g.Map{"flag":true}) // 更改子域名扫描状态
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
	logger.WebLog.Debugf("[+] [端口扫描] [%s]成功扫描到[%d]个端口", r[0].Host, len(r))
	return nil
}

// utilPortScanPush 处理端口扫描结果
func utilPortScanPush(r []Gnsq.ResponsePortScanStruct)error{
	time.Sleep(1*time.Second)
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-","",-1)
	res,err := dao.UtilPortscanTask.Where("cus_name=?",CusName).FindOne()
	if err != nil{
		logger.WebLog.Warningf("[-] [Util-端口扫描扫描消费者] 数据库查询对应任务名失败：%s", err.Error())
		return err
	}
	if res == nil{
		return nil
	}
	if _,err = dao.UtilPortscanTask.Update(g.Map{"scan_num":res.ScanNum+1}, "cus_name", CusName);err != nil{
		logger.WebLog.Warningf("[-] [Util-端口扫描扫描消费者] 修改已扫描数失败:%s", err.Error())
		return err
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