package pushmsg

import (
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/dao"
	"github.com/CTF-MissFeng/GoScan/Web/app/model"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	"github.com/CTF-MissFeng/GoScan/Web/library/nsq/producer"
	"github.com/CTF-MissFeng/GoScan/Web/library/util/screenshot"

	"github.com/gogf/gf/container/gset"
	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/os/gtime"
)

// PushDomain 投递子域名扫描
func PushDomain(cusName string){
	result, err := dao.ScanDomain.Where("cus_name=? AND nsq_flag=?",cusName,false).FindAll()
	if err != nil{
		logger.WebLog.Warningf("[-] 子域名投递消息  数据库查询错误:%s", err.Error())
		return
	}
	if result == nil || len(result) == 0{
		return
	}
	pubMessages := make([]model.ScanDomainApiAddReq,0)
	for _,v := range result{
		pubMessages = append(pubMessages, model.ScanDomainApiAddReq{CusName: v.CusName, Domain: v.Domain})
	}
	_,err = dao.ScanDomain.Where("cus_name=? AND nsq_flag=?",cusName, false).Update(g.Map{"nsq_flag":true})
	if err != nil {
		logger.WebLog.Warningf("[-] 子域名投递消息  修改主域名状态失败:%s", err.Error())
		return
	}
	producer.PubSubDomain(pubMessages)
}

// PushPortScan 投递端口扫描
func PushPortScan(){
	result,err := dao.ScanSubdomain.Where("flag=? and nsq_flag=? and cdn=? and ip<>?", false, false, false, "null").All()
	if err != nil{
		logger.WebLog.Warningf("[-] [投递端口扫描] 获取端口扫描数据失败:%s", err.Error())
		return
	}
	if result == nil || len(result)==0{
		return
	}
	iplist := gset.NewStrSet() // IP去重
	pullresult := make([]model.UtilPortScanApiAddReq, 0)
	for _,v := range result{
		if iplist.ContainsI(v.Ip){
			continue
		}
		iplist.Add(v.Ip)
		pullresult = append(pullresult, model.UtilPortScanApiAddReq{
			CusName: v.CusName,
			Hosts: v.Ip,
		})
	}
	_,err = dao.ScanSubdomain.Where("flag=? and nsq_flag=? and cdn=? and ip<>?",false, false, false, "null").Update(g.Map{"nsq_flag": true}) // 更新投递状态
	if err != nil {
		logger.WebLog.Warningf("[-] [投递端口扫描] 更新子域名投递状态失败:%s", err.Error())
		return
	}
	producer.PortScanSendMessage(pullresult)
}

// pushWebInfo 投递web探测
func pushWebInfo(){
	result,err := dao.ScanPort.Where("flag=? and nsq_flag=? and http_flag=?", false, false, true).All()
	if err != nil{
		logger.WebLog.Warningf("[-] [投递Web探测] 获取所需扫描数据失败:%s", err.Error())
		return
	}
	if result == nil || len(result)==0{
		return
	}
	pullMsgs := make([]model.NsqPushWeb, 0)
	for _,v := range result {
		res,err := dao.ScanSubdomain.Where("ip=?", v.Host).All()
		if err != nil{
			logger.WebLog.Warningf("[-] [投递Web探测] 查找子域名数据库错误:%s", err.Error())
			return
		}
		subdomains := make([]string,0)
		for i,v1 := range res{
			if i > 100{
				break
			}
			subdomains = append(subdomains, v1.Subdomain)
		}
		if len(subdomains) == 0{
			continue
		}
		pullMsgs = append(pullMsgs, model.NsqPushWeb{
			CusName: v.CusName,
			SubDomain: subdomains,
			ServiceName: v.ServiceName,
			Port: v.Port,
			Ip: v.Host,
		})
	}
	if len(pullMsgs) == 0{
		return
	}
	_,err = dao.ScanPort.Where("flag=? and nsq_flag=? and http_flag=?",false,false,true).Update(g.Map{"nsq_flag": true}) // 更新投递状态
	if err != nil {
		logger.WebLog.Warningf("[-] [投递Web探测] 更新端口投递状态失败:%s", err.Error())
		return
	}
	producer.PubWebInfo(pullMsgs)
}

// pushWebInfoCdn 投递CDN web探测
func pushWebInfoCdn(){
	result,err := dao.ScanSubdomain.Where("flag=? and nsq_flag=? and cdn=?", false, false, true).All()
	if err != nil{
		logger.WebLog.Warningf("[-] [投递Web探测CDN] 获取所需扫描数据失败:%s", err.Error())
		return
	}
	if result == nil || len(result)==0{
		return
	}
	pullMsgs := make([]model.NsqPushWeb, 0)
	for _,v := range result {
		pullMsgs = append(pullMsgs, model.NsqPushWeb{
			CusName: "CDN" + v.CusName,
			SubDomain: []string{v.Subdomain},
			ServiceName: "http",
			Port: 80,
			Ip:v.Ip,
		})
	}
	if len(pullMsgs) == 0 {
		return
	}
	_,err = dao.ScanSubdomain.Where("flag=? and nsq_flag=? and cdn=?", false, false, true).Update(g.Map{"nsq_flag": true})
	if err != nil {
		logger.WebLog.Warningf("[-] [投递Web探测CDN] 更新子域名投递状态失败:%s", err.Error())
		return
	}
	producer.PubWebInfo(pullMsgs)
}

// 定时投递消息
func TimingPush(){
	ReadNsq()
	for{
		PushPortScan()
		pushWebInfo()
		pushWebInfoCdn()
		time.Sleep(2 * time.Minute)
	}
}

// 读取Nsq消息地址配置
func ReadNsq(){
	var nsqInfo model.APIKeyEngineNsqReq
	nsqInfo.NsqHost = g.Cfg().GetString("nsq.TcpHost")
	nsqInfo.NsqHttp = g.Cfg().GetString("nsq.HttpHost")
	nsqInfo.Time = 999
	count,err := dao.ApiKey.Where("key=?", "engine_nsq").Count()
	if err != nil {
		return
	}
	if count == 0{
		jsonstr,err := gjson.New(nsqInfo).ToJsonString()
		if err == nil {
			dao.ApiKey.Insert(g.Map{"key":"engine_nsq","value":jsonstr})
		}
	}
}

// webScreenshot web截图
func webScreenshot(Url string)(string, error){
	filename := gfile.Join("public/screenshot", gtime.TimestampMicroStr()+".png")
	s1 := screenshot.Config{
		Timeout: 10,
		Url: Url,
		FileName: filename,
	}
	err := s1.Run()
	if err != nil{
		logger.WebLog.Warningf("[-] web截图失败:%s", err.Error())
		return "",err
	}
	return filename,nil
}

// TimingWebScreenshot
func TimingWebScreenshot(){
	for{
		time.Sleep(2*time.Second)
		result,err := dao.ScanWeb.Where("screenshot_flag=?",false).FindOne()
		if err != nil{
			logger.WebLog.Warningf("[-] web截图查询数据库失败:%s", err.Error())
			continue
		}
		if result == nil{
			time.Sleep(1*time.Minute)
			continue
		}
		filename, err := webScreenshot(result.Url)
		if err != nil{
			continue
		}
		if _,err = dao.ScanWeb.Update(g.Map{"screenshot_flag": true,"image":filename},"url",result.Url); err != nil{
			logger.WebLog.Warningf("[-] web截图更新状态失败:%s", err.Error())
		}
	}
}