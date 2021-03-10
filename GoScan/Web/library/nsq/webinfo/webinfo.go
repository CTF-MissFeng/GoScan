package webinfo

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/dao"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	"github.com/CTF-MissFeng/GoScan/Web/library/util/dnsprobe"
	"github.com/CTF-MissFeng/GoScan/Web/library/util/ipquery"

	"github.com/gogf/gf/container/gset"
	"github.com/gogf/gf/encoding/gbase64"
	"github.com/gogf/gf/frame/g"
	"github.com/nsqio/go-nsq"
)

// web探测 消费者类型
type Handler struct {
	Title string
}

// web探测 初始化消费者
func InitConsumer(topic string, channel string) {
	config := nsq.NewConfig()
	config.MsgTimeout = 10 * time.Minute
	if err := config.Validate(); err != nil{
		logger.WebLog.Fatalf("[-] [web探测消费者] 配置文件错误:%s", err.Error())
	}
	consumer, err := nsq.NewConsumer(topic, channel, config)
	if err != nil {
		logger.WebLog.Fatalf("[-] [web探测消费者] 创建消费者任务队列失败:%s", err.Error())
	}
	client := &Handler{
		Title: "server",
	}
	consumer.AddHandler(client)
	if err1 := consumer.ConnectToNSQD(g.Cfg().GetString("nsq.TcpHost")); err1 != nil{
		logger.WebLog.Fatalf("[-] [web探测消费者] 连接任务队列服务器失败:%s", err1.Error())
	}
	logger.WebLog.Infof("[+] [web探测消费者] 连接任务队列服务器成功")
}

// 返回结果格式
type SendMessageStruct struct{
	CusName string `json:"cus_name"`
	Host string `json:"host"`
	Data []ResultWebInfo `json:"data"`
}

// ResultWebInfo web探测返回信息
type ResultWebInfo struct{
	Url string `json:"url"`
	StatusCode int `json:"status_code"`
	Title string `json:"title"`
	ContentLength int `json:"content_length"`
	Banalyze map[string]ResultApp `json:"banalyze"`
	SubDomaina []string `json:"subdomaina"`
	Js []string `json:"js"`
	Urls []string `json:"urls"`
	Forms []string `json:"forms"`
	Keys []string `json:"keys"`
}

// resultApp 指纹识别结果
type ResultApp struct {
	Name       string   `json:"name"`
	Version    []string	`json:"version"`
	Implies    []string `json:"implies"`
	Description string  `json:"description"`
}

// 接受nsqd消息
func (m *Handler) HandleMessage(msg *nsq.Message) error {
	if len(msg.Body) == 0{
		return nil
	}
	var results SendMessageStruct
	msgStr, err := gbase64.Decode(msg.Body)
	if err != nil{
		logger.WebLog.Warningf("[-] [Web探测消费者] Base64解码消息失败:%s", err.Error())
		return nil
	}
	if err = json.Unmarshal(msgStr,&results); err != nil{
		logger.WebLog.Warningf("[-] [Web探测消费者] Json反序列化失败:%s", err.Error())
		return nil
	}
	if len(results.Data) == 0{
		logger.WebLog.Warningf("[-] [Web探测消费者] 解码后空数据")
		return nil
	}
	return WebInfoPush(&results)
}

var GsubDomains gset.StrSet // 保存所有爬虫得到的子域名,减轻数据库压力

// WebInfoPush 处理web探测结果
func WebInfoPush(s *SendMessageStruct)error{
	time.Sleep(1*time.Second)
	if strings.HasPrefix(s.CusName,"CDN"){
		CdnCusName := s.CusName[3:len(s.CusName)]
		_,err := dao.ScanSubdomain.Where("cus_name=?", CdnCusName).Update(g.Map{"flag":true})
		if err != nil {
			logger.WebLog.Warningf("[-] [web探测CDN] :更新子域名扫描状态失败%s", err.Error())
			return err
		}
	}else{
		portResult,err := dao.ScanPort.Where("cus_name=? AND host=? AND nsq_flag=?",s.CusName,s.Host,true).FindOne()
		if err != nil {
			logger.WebLog.Warningf("[-] [web探测] 查询端口数据错误:%s", err.Error())
			return err
		}
		if portResult == nil{
			return nil
		}
		if !portResult.Flag{
			_,err1 := dao.ScanPort.Where("cus_name=? AND host=? AND nsq_flag=?",s.CusName,s.Host,true).Update(g.Map{"flag":true}) // 更改端口web探测状态
			if err1 != nil {
				logger.WebLog.Warningf("[-] [web探测] 更改端口扫描状态失败:%s", err1.Error())
				return err1
			}
		}
	}

	subDomains := gset.NewStrSet() // 爬虫子域名去重
	for _,v := range s.Data{
		if len(v.SubDomaina) != 0{
			for _,sub := range v.SubDomaina{
				if !GsubDomains.ContainsI(sub){
					subDomains.Add(strings.Trim(sub," "))
					GsubDomains.Add(strings.Trim(sub," "))
				}
			}
		}
		js := ""
		if len(v.Js) != 0{
			js = strings.Join(v.Js, "\n")
		}
		urls := ""
		if len(v.Urls) != 0{
			urls = strings.Join(v.Urls, "\n")
		}
		forms := ""
		if len(v.Forms) != 0{
			forms = strings.Join(v.Forms, "\n")
		}
		secret := ""
		if len(v.Keys) != 0{
			secret = strings.Join(v.Keys, "\n")
		}
		banalyze :=  bytes.Buffer{}
		if len(v.Banalyze) != 0{
			for _,v1 := range v.Banalyze {
				banalyze.WriteString(v1.Name)
				banalyze.WriteString("-")
				if len(v1.Version) != 0{
					banalyze.WriteString(strings.Join(v1.Version, ","))
					banalyze.WriteString("-")
				}
				if len(v1.Implies) != 0{
					banalyze.WriteString(strings.Join(v1.Implies, ","))
					banalyze.WriteString("-")
				}
				banalyze.WriteString(v1.Description)
				banalyze.WriteString("\n")
			}
		}else{
			banalyze.WriteString("无指纹")
		}
		urlCount,err := dao.ScanWeb.Where("url=?", v.Url).Count()
		if err == nil && urlCount == 0 {
			CusName := s.CusName
			if strings.HasPrefix(s.CusName,"CDN"){
				CusName = s.CusName[3:len(s.CusName)]
			}
			insertStruct := g.Map{
				"cus_name": CusName,
				"url": v.Url,
				"code": v.StatusCode,
				"title": v.Title,
				"content_length":v.ContentLength,
				"js": js,
				"urls": urls,
				"forms": forms,
				"secret": secret,
				"fingerprint":banalyze.String(),
				"flag":false,
				"nsq_flag":false,
				"screenshot_flag": false,
			}
			_,err1 := dao.ScanWeb.Insert(insertStruct)
			if err1 != nil {
				logger.WebLog.Warningf("[-] [web探测结果] 插入到数据库错误:%s", err1.Error()[1:100])
			}
		}else{
			if err != nil {
				logger.WebLog.Warningf("[-] [web探测结果] 查询url数据库错误:%s", err.Error())
				continue
			}else if urlCount > 0{
				logger.WebLog.Warningf("[-] [web探测结果] 发现重复web信息:%s", v.Url)
				return nil
			}
		}
	}
	if subDomains.Size() == 0{
		return nil
	}
	results,err := dnsprobe.Run(subDomains.Slice())
	if err != nil {
		logger.WebLog.Warningf("[web探测] 爬虫新增子域名解析错误:%s", err.Error())
		return nil
	}
	if results == nil{
		return nil
	}
	logger.WebLog.Debugf("[web探测] 爬虫找到子域名：%d个", subDomains.Size())
	for _, v := range results {
		if len(v.IP) == 0{
			continue
		}
		count, err := dao.ScanSubdomain.Where("ip=?", v.IP[0]).Count()
		if err != nil{
			logger.WebLog.Warningf("[web探测] 爬虫新增子域名 查询IP数据库错误:%s", err.Error())
			continue
		}
		if count == 0{
			domainCount,err := dao.ScanSubdomain.Where("subdomain=?", v.SubDomain).Count()
			if err != nil {
				logger.WebLog.Warningf("[web探测] 爬虫新增子域名 查询子域名数据库错误:%s", err.Error())
				continue
			}
			if domainCount > 0{
				logger.WebLog.Warningf("[web探测] 爬虫新增子域名 [%s]子域名已存在", v.SubDomain)
				continue
			}
			ipinfo,_ := ipquery.QueryIp(v.IP[0])
			location := ""
			if ipinfo != nil{
				location = ipinfo.String()
			}
			CusName := s.CusName
			if strings.HasPrefix(s.CusName,"CDN"){
				CusName = s.CusName[3:len(s.CusName)]
			}
			_,err = dao.ScanSubdomain.Insert(g.Map{
				"cus_name": CusName,
				"domain": "爬虫新增",
				"subdomain": v.SubDomain,
				"ip": v.IP[0],
				"cname": strings.Join(v.CNAME, ","),
				"cdn": v.Cdn,
				"location": location,
				"flag": false,
				"nsq_flag": false,
			})
			if err != nil {
				logger.WebLog.Warningf("[-] [web探测] 爬虫新增子域名入库失败:%s", err.Error())
				continue
			}else{
				logger.WebLog.Debugf("[+] [web爬虫] 新增[%s]厂商[%s]子域名成功", s.CusName,v.SubDomain)
			}
		}
	}
	return nil
}