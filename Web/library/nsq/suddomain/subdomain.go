package suddomain

import (
	"bytes"
	"encoding/gob"
	"strings"
	"time"

	"Web/app/dao"
	"Web/app/model"
	"Web/library/logger"
	"Web/library/nsq/producer"
	"Web/library/util/ipquery"

	"github.com/gogf/gf/container/gset"
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
	config.MsgTimeout = 100 * time.Second // 设置消息反馈超时时间
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
	err1 := consumer.ConnectToNSQD(g.Cfg().GetString("nsq.CTcpHost")) // 连接到nsqd
	if err1 != nil{
		logger.WebLog.Fatalf("[-] [子域名消费者] 连接任务队列服务器失败:%s", err1.Error())
	}else{
		logger.WebLog.Infof("[+] [子域名消费者] 连接任务队列服务器成功")
	}
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

// 子域名扫描 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil
	}
	var DomainInfo []SendMessageStruct
	dec := gob.NewDecoder(bytes.NewReader(msg.Body))
	err := dec.Decode(&DomainInfo)
	if err != nil{
		logger.WebLog.Warningf("[-] [子域名扫描] 消息解码失败:%s", err.Error())
		return err
	}
	if strings.Contains(DomainInfo[0].CusName, "util-"){
		if err = utilsubDomainPush(DomainInfo); err != nil{
			return err
		}
	}else{
		if err = subDomainPush(DomainInfo); err != nil{
			return err
		}
		pushPortScan(DomainInfo[0].CusName)
	}
	return nil
}

// subDomainPush 处理子域名结果
func subDomainPush(r []SendMessageStruct)error{
	_,err := dao.ScanDomain.Where("domain=?",r[0].Domain).Update(g.Map{"flag":true}) // 更改主域名扫描状态
	if err != nil {
		logger.WebLog.Warningf("[-] [子域名扫描] 更改主域名扫描状态失败:%s", err.Error())
		return err
	}
	if len(r) == 1{ // 处理没有结果的
		if r[0].Subdomain == "null"{
			return nil
		}
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
func utilsubDomainPush(r []SendMessageStruct)error{
	CusName := r[0].CusName
	CusName = strings.Replace(CusName, "util-","",-1)
	res,err := dao.UtilSubdomainTask.Where("cus_name=?",CusName).FindOne()
	if err != nil || res == nil{
		logger.WebLog.Warningf("[-] [Util-子域名扫描消费者] 数据库查询对应任务名失败：%s", err.Error())
		return nil
	}
	if _,err = dao.UtilSubdomainTask.Update(g.Map{"scan_num":res.ScanNum+1}, "cus_name", CusName);err != nil{
		logger.WebLog.Warningf("[-] [Util-子域名扫描消费者] 修改已扫描数失败:%s", err.Error())
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

// pushPortScan 子域名扫描完投递端口扫描
func pushPortScan(CusName string){
	result,err := dao.ScanSubdomain.Where("cus_name=? and flag=? and nsq_flag=? and cdn=? and ip<>?", CusName, false, false, false, "null").All()
	if err != nil{
		logger.WebLog.Warningf("[-] [端口扫描] 获取端口扫描数据失败:%s", err.Error())
		return
	}
	if result == nil || len(result)==0{
		logger.WebLog.Warningf("[-] [端口扫描] 获取端口扫描无数据")
		return
	}
	iplist := gset.NewStrSet() // IP去重
	for _,v := range result{
		iplist.Add(v.Ip)
	}
	pullresult := make([]model.ApiUtilPortScanAddReq, 0)
	for _,host := range iplist.Slice(){
		pullresult = append(pullresult, model.ApiUtilPortScanAddReq{
			CusName: CusName,
			Hosts: host,
		})
	}
	_,err = dao.ScanSubdomain.Where("cus_name=?",CusName).Update(g.Map{"nsq_flag": true}) // 更新投递状态
	if err != nil {
		logger.WebLog.Warningf("[-] [端口扫描] 更新子域名状态失败:%s", err.Error())
		return
	}
	go producer.PortScanSendMessage(pullresult)
}