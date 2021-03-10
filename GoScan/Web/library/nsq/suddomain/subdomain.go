package suddomain

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/dao"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Web/library/nsq"
	"github.com/CTF-MissFeng/GoScan/Web/library/util/ipquery"

	"github.com/gogf/gf/encoding/gbase64"
	"github.com/gogf/gf/frame/g"
	"github.com/nsqio/go-nsq"
)

// 子域名扫描 消费者类型
type Handler struct {
	Title string
}

// 子域名扫描 初始化消费者
func InitConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 10 * time.Minute
	if err := config.Validate(); err != nil{
		logger.WebLog.Fatalf("[-] [子域名消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.WebLog.Fatalf("[-] [子域名消费者] 创建消费者任务队列失败:%s", err.Error())
	}
	client := &Handler{
		Title: "server",
	}
	consumer.AddHandler(client)
	if err1 := consumer.ConnectToNSQD(g.Cfg().GetString("nsq.TcpHost")); err1 != nil{
		logger.WebLog.Fatalf("[-] [子域名消费者] 连接任务队列服务器失败:%s", err1.Error())
	}
	logger.WebLog.Infof("[+] [子域名消费者] 连接任务队列服务器成功")
}

// 子域名扫描 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil
	}
	var DomainInfo []Gnsq.ResponseSubDomainStruct
	msgStr, err := gbase64.Decode(msg.Body)
	if err != nil{
		logger.WebLog.Warningf("[-] [子域名扫描消费者] Base64解码消息失败:%s", err.Error())
		return nil
	}
	if err = json.Unmarshal(msgStr,&DomainInfo); err != nil{
		logger.WebLog.Warningf("[-] [子域名扫描消费者] Json反序列化失败:%s", err.Error())
		return nil
	}
	if len(DomainInfo) == 0{
		logger.WebLog.Warningf("[-] [子域名扫描消费者] 解码后无数据")
		return nil
	}
	if strings.Contains(DomainInfo[0].CusName, "util-"){
		return utilsubDomainPush(DomainInfo)
	}
	return subDomainPush(DomainInfo)
}

// subDomainPush 处理子域名结果
func subDomainPush(r []Gnsq.ResponseSubDomainStruct)error{
	time.Sleep(2*time.Second)
	res, err := dao.ScanDomain.Where("domain=? AND nsq_flag=?", r[0].Domain, true).FindOne()
	if err != nil{
		logger.WebLog.Warningf("[-] [子域名扫描] 查询主域名扫描状态失败:%s", err.Error())
		return err
	}
	if !res.Flag{
		_,err1 := dao.ScanDomain.Where("domain=? AND nsq_flag=?",r[0].Domain, true).Update(g.Map{"flag":true}) // 更改主域名扫描状态
		if err1 != nil {
			logger.WebLog.Warningf("[-] [子域名扫描] 更改主域名扫描状态失败:%s", err.Error())
			return err1
		}
	}

	if len(r) == 1{ // 处理没有结果的
		if r[0].Subdomain == "null"{
			logger.WebLog.Debugf("[-] [子域名扫描] [%s]主域名未发现子域名", r[0].Domain)
			return nil
		}
	}
	subdomainCount,err := dao.ScanSubdomain.Where("subdomain=?",r[0].Subdomain).Count()
	if err != nil {
		logger.WebLog.Warningf("[-] [子域名扫描] 查询子域名数据库错误:%s", err.Error())
		return err
	}
	if subdomainCount != 0{
		logger.WebLog.Warningf("[-] [子域名扫描] [%s]子域名已存在，发现重复子域名扫描数据", r[0].Subdomain)
		return nil
	}
	Ips := make(map[string]string,0) // 建立map 减少ip查询
	for i := 0; i < len(r); i++{
		if !strings.Contains(r[i].Ip, ","){
			if v,ok := Ips[r[i].Ip]; ok {
				r[i].Location = v
				continue
			}
			ipinfo,err := ipquery.QueryIp(r[i].Ip)
			if err != nil {
				continue
			}
			Ips[r[i].Ip] = ipinfo.String()
			r[i].Location = ipinfo.String()
		}
	}
	if _,err = dao.ScanSubdomain.Insert(r); err != nil{ // 批量插入
		logger.WebLog.Warningf("[-] [子域名扫描] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}

// utilsubDomainPush 处理子域名结果
func utilsubDomainPush(r []Gnsq.ResponseSubDomainStruct)error{
	time.Sleep(2*time.Second)
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-","",-1)
	res,err := dao.UtilSubdomainTask.Where("cus_name=?",CusName).FindOne()
	if err != nil{
		logger.WebLog.Warningf("[-] [Util-子域名扫描消费者] 数据库查询对应任务名失败：%s", err.Error())
		return err
	}
	if res == nil{
		return nil
	}
	if res.ScanNum < res.DomainNum{
		if _,err = dao.UtilSubdomainTask.Update(g.Map{"scan_num":res.ScanNum+1}, "cus_name", CusName);err != nil{
			logger.WebLog.Warningf("[-] [Util-子域名扫描消费者] 修改已扫描数失败:%s", err.Error())
		}
	}
	if len(r) == 1{ // 处理没有结果的
		if r[0].Subdomain == "null"{
			return nil
		}
	}
	Ips := make(map[string]string,0) // 建立map 减少ip查询
	for i := 0; i < len(r); i++{
		r[i].CusName = strings.Replace(r[i].CusName, "util-","",-1)
		if !strings.Contains(r[i].Ip, ","){
			if v,ok := Ips[r[i].Ip]; ok {
				r[i].Location = v
				continue
			}
			ipinfo,err := ipquery.QueryIp(r[i].Ip)
			if err != nil {
				continue
			}
			Ips[r[i].Ip] = ipinfo.String()
			r[i].Location = ipinfo.String()
		}
	}
	if _,err = dao.UtilSubdomainResult.Insert(r); err != nil{ // 批量插入
		logger.WebLog.Warningf("[-] [Util-子域名扫描消费者] 保存结果失败:%s", err.Error())
		return nil
	}
	return nil
}