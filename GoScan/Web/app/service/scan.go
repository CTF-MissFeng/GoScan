package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/dao"
	"github.com/CTF-MissFeng/GoScan/Web/app/model"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Web/library/nsq"
	"github.com/CTF-MissFeng/GoScan/Web/library/nsq/producer"
	"github.com/CTF-MissFeng/GoScan/Web/library/nsq/pushmsg"
	"github.com/CTF-MissFeng/GoScan/Web/library/util/banalyze"

	"github.com/gogf/gf/container/gset"
	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/text/gstr"
	"github.com/gogf/gf/util/gconv"
	"github.com/gogf/gf/util/gvalid"
)

var Scan = new(serviceScan)

type serviceScan struct{}

// APIKeyEngineNsqAdd 扫描引擎 添加nsq地址
func (s *serviceScan) APIKeyEngineNsqAdd(r *model.APIKeyEngineNsqReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_nsq").Count()
	if err != nil {
		logger.WebLog.Warningf("查询扫描引擎nsq数据库错误:%s", err.Error())
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-nsq序列化失败:%s", err.Error())
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_nsq"); err != nil{
			logger.WebLog.Warningf("扫描引擎-nsq更新失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_nsq","value":jsonstr}); err != nil{
			logger.WebLog.Warningf("扫描引擎-nsq保存失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEnginePortScanAdd 扫描引擎 添加端口扫描
func (s *serviceScan) ApiKeyEnginePortScanAdd(r *model.ApiKeyEnginePortScanReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_portscan").Count()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-端口扫描查询数据库失败:%s", err.Error())
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-端口扫描序列化失败:%s", err.Error())
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_portscan"); err != nil{
			logger.WebLog.Warningf("扫描引擎-端口扫描更新失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_portscan","value":jsonstr}); err != nil{
			logger.WebLog.Warningf("扫描引擎-端口扫描保存失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEngineDomainAdd 扫描引擎 添加子域名
func (s *serviceScan) ApiKeyEngineDomainAdd(r *model.ApiKeyEngineDomainReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_domain").Count()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-子域名查询失败:%s", err.Error())
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-子域名序列化失败:%s", err.Error())
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_domain"); err != nil{
			logger.WebLog.Warningf("扫描引擎-子域名更新失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_domain","value":jsonstr}); err != nil{
			logger.WebLog.Warningf("扫描引擎-子域名保存失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEngineKeyAdd 扫描引擎 添加API秘钥
func (s *serviceScan) ApiKeyEngineKeyAdd(r *model.ApiKeyEngineKeyReq)error{
	count,err := dao.ApiKey.Where("key=?", "engine_apikey").Count()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-API秘钥查询失败:%s", err.Error())
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-API秘钥序列化失败:%s", err.Error())
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_apikey"); err != nil{
			logger.WebLog.Warningf("扫描引擎-API秘钥更新失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_apikey","value":jsonstr}); err != nil{
			logger.WebLog.Warningf("扫描引擎-API秘钥保存失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEngineWebInfoAdd 扫描引擎 添加Web探测
func (s *serviceScan) ApiKeyEngineWebInfoAdd(r *model.ApiKeyEngineWebInfoReq)error{
	count,err := dao.ApiKey.Where("key=?", "engine_webinfo").Count()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-web探测查询失败:%s", err.Error())
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		logger.WebLog.Warningf("扫描引擎-web探测序列化失败:%s", err.Error())
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_webinfo"); err != nil{
			logger.WebLog.Warningf("扫描引擎-web探测更新失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_webinfo","value":jsonstr}); err != nil{
			logger.WebLog.Warningf("扫描引擎-web探测保存失败:%s", err.Error())
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// GetApiKeyEngine 扫描引擎 输出配置
func (s *serviceScan) GetApiKeyEngine()*model.ResApiKeyEngine{
	result := model.ResApiKeyEngine{}

	jsonNsq,err := dao.ApiKey.Where("key=?", "engine_nsq").FindOne()
	if err == nil && jsonNsq != nil{
		j,err := gjson.DecodeToJson(jsonNsq.Value)
		structs := model.APIKeyEngineNsqReq{}
		if err == nil {
			err = j.Struct(&structs)
			if err == nil{
				result.Nsq = structs
			}
		}
	}
	jsonPortScan,err := dao.ApiKey.Where("key=?", "engine_portscan").FindOne()
	if err == nil && jsonPortScan != nil{
		j,err := gjson.DecodeToJson(jsonPortScan.Value)
		structs := model.ApiKeyEnginePortScanReq{}
		if err == nil {
			err = j.Struct(&structs)
			if err == nil{
				result.PortScan = structs
			}
		}
	}
	jsonDomain,err := dao.ApiKey.Where("key=?", "engine_domain").FindOne()
	if err == nil && jsonDomain != nil{
		j,err := gjson.DecodeToJson(jsonDomain.Value)
		structs := model.ApiKeyEngineDomainReq{}
		if err == nil {
			err = j.Struct(&structs)
			if err == nil{
				result.Domain = structs
			}
		}
	}
	jsonApiKey,err := dao.ApiKey.Where("key=?", "engine_apikey").FindOne()
	if err == nil && jsonApiKey != nil{
		j,err := gjson.DecodeToJson(jsonApiKey.Value)
		structs := model.ApiKeyEngineKeyReq{}
		if err == nil {
			err = j.Struct(&structs)
			if err == nil{
				structs.Binaryedge = "******"
				structs.CensysSecret = "******"
				structs.CensysToken = "******"
				structs.Certspotter = "******"
				structs.GitHub = "******"
				structs.Shodan = "******"
				structs.Spyse = "******"
				structs.URLScan = "******"
				structs.ThreatBook = "******"
				structs.Virustotal = "******"
				structs.Securitytrails = "******"
				result.ApiKey = structs
			}
		}
	}

	jsonWebInfo,err := dao.ApiKey.Where("key=?", "engine_webinfo").FindOne()
	if err == nil && jsonWebInfo != nil{
		j,err := gjson.DecodeToJson(jsonWebInfo.Value)
		structs := model.ApiKeyEngineWebInfoReq{}
		if err == nil {
			err = j.Struct(&structs)
			if err == nil{
				result.WebInfo = structs
			}
		}
	}
	jsonBanalyze,err := dao.Banalyze.Where("1=?",1).FindAll()
	if err == nil && jsonBanalyze != nil{
		var exportData []*banalyze.App
		for _,v := range jsonBanalyze{
			jsonList,err := banalyze.LoadApps([]byte(v.Value))
			if err != nil{
				continue
			}
			exportData = append(exportData, jsonList.Apps[0])
		}
		result.Banalyze = exportData
	}


	return &result
}

// EmptyPort 端口扫描清空消息队列
func (s *serviceScan) EmptyPort() error {
	return producer.NsqTopicEmpty(Gnsq.PortScanTopic, Gnsq.PortScanTopicChanl)
}

// EmptyDomain 子域名清空消息队列
func (s *serviceScan) EmptyDomain() error {
	return producer.NsqTopicEmpty(Gnsq.SubDomainTopic, Gnsq.SubDomainChanl)
}

// EmptyWebInfo Web探测清空消息队列
func (s *serviceScan) EmptyWebInfo() error {
	return producer.NsqTopicEmpty(Gnsq.WebInfoTopic, Gnsq.RWebInfoChanl)
}

// PortNSqStats 端口扫描管理 Nsqd详情
func (s *serviceScan) PortNSqStats()*model.NsqResInfo{
	jsondata, err := producer.NsqStatsInfo(Gnsq.PortScanTopic)
	if err != nil {
		return &model.NsqResInfo{Code:0,Msg:"获取消息队列信息失败",Count:0,Data:nil}
	}
	message_count := 0 // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0 // 客户端数
	timeout_count := 0 // 超时数
	result := make([]model.NsqResInfos, 0)
	for _, v := range jsondata.Topics{
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels{
			if k.ChannelName == Gnsq.PortScanTopicChanl{
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients{
					result = append(result, model.NsqResInfos{
						Hostname: y.Hostname, // 客户端主机名
						RemoteAddress: y.RemoteAddress, // 客户端地址
						MessageCount: y.MessageCount, // 客户端消息数
						FinishCount: y.FinishCount, // 客户端完成数
						ConnectTs: time.Unix(y.ConnectTs, 0).Format("2006-01-02 15:04:05") ,
					})
				}
				break // 找到chanl就跳出循环
			}
		}
	}
	if len(result) == 0{
		return &model.NsqResInfo{Code:0,Msg:"无客户端",Count:0,Data:nil,MessageCount: message_count,
			MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
	}
	return &model.NsqResInfo{Code:0,Msg:"ok",Count:0,Data:result,MessageCount: message_count,
		MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
}

// DomainNSqStats 子域名扫描管理 Nsqd详情
func (s *serviceScan) DomainNSqStats()*model.NsqResInfo{
	jsondata, err := producer.NsqStatsInfo(Gnsq.SubDomainTopic)
	if err != nil {
		return &model.NsqResInfo{Code:0,Msg:"获取消息队列信息失败",Count:0,Data:nil}
	}
	message_count := 0 // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0 // 客户端数
	timeout_count := 0 // 超时数
	result := make([]model.NsqResInfos, 0)
	for _, v := range jsondata.Topics{
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels{
			if k.ChannelName == Gnsq.SubDomainChanl{
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients{
					result = append(result, model.NsqResInfos{
						Hostname: y.Hostname, // 客户端主机名
						RemoteAddress: y.RemoteAddress, // 客户端地址
						MessageCount: y.MessageCount, // 客户端消息数
						FinishCount: y.FinishCount, // 客户端完成数
						ConnectTs: time.Unix(y.ConnectTs, 0).Format("2006-01-02 15:04:05") ,
					})
				}
				break // 找到chanl就跳出循环
			}
		}
	}
	if len(result) == 0{
		return &model.NsqResInfo{Code:0,Msg:"无客户端",Count:0,Data:nil,MessageCount: message_count,
			MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
	}
	return &model.NsqResInfo{Code:0,Msg:"ok",Count:0,Data:result,MessageCount: message_count,
		MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
}

// WebInfoNSqStats Web探测管理 Nsqd详情
func (s *serviceScan) WebInfoNSqStats()*model.NsqResInfo{
	jsondata, err := producer.NsqStatsInfo(Gnsq.WebInfoTopic)
	if err != nil {
		return &model.NsqResInfo{Code:0,Msg:"获取消息队列信息失败",Count:0,Data:nil}
	}
	message_count := 0 // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0 // 客户端数
	timeout_count := 0 // 超时数
	result := make([]model.NsqResInfos, 0)
	for _, v := range jsondata.Topics{
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels{
			if k.ChannelName == Gnsq.WebInfoChanl{
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients{
					result = append(result, model.NsqResInfos{
						Hostname: y.Hostname, // 客户端主机名
						RemoteAddress: y.RemoteAddress, // 客户端地址
						MessageCount: y.MessageCount, // 客户端消息数
						FinishCount: y.FinishCount, // 客户端完成数
						ConnectTs: time.Unix(y.ConnectTs, 0).Format("2006-01-02 15:04:05") ,
					})
				}
				break // 找到chanl就跳出循环
			}
		}
	}
	if len(result) == 0{
		return &model.NsqResInfo{Code:0,Msg:"无客户端",Count:0,Data:nil,MessageCount: message_count,
			MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
	}
	return &model.NsqResInfo{Code:0,Msg:"ok",Count:0,Data:result,MessageCount: message_count,
		MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
}

// ManagerAdd 添加厂商
func (s *serviceScan) ManagerAdd(r *model.ApiScanManagerAddReq)error{
	count,err := dao.ScanHome.Where("cus_name=?", r.CusName).Count()
	if err != nil{
		logger.WebLog.Warningf("综合扫描-添加厂商失败:%s", err.Error())
		return errors.New("添加厂商失败,数据库错误")
	}
	if count > 0{
		return errors.New("添加厂商失败,已存在该厂商")
	}
	_,err = dao.ScanHome.Insert(r)
	if err != nil{
		logger.WebLog.Warningf("综合扫描-添加厂商失败:%s", err.Error())
		return errors.New("添加厂商失败,数据库错误")
	}
	return nil
}

// ManagerDelete 删除厂商
func (s *serviceScan) ManagerDelete(r *model.ApiScanManagerDeleteReq)error{
	count,err := dao.ScanHome.Where("cus_name=?", r.CusName).Count()
	if err != nil{
		logger.WebLog.Warningf("综合扫描-删除厂商失败:%s", err.Error())
		return errors.New("删除厂商失败,数据库错误")
	}
	if count == 0{
		return errors.New("删除厂商失败,该厂商不存在")
	}
	if _,err = dao.ScanHome.Where("cus_name=?",r.CusName).Delete(); err != nil{
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _,err = dao.ScanDomain.Where("cus_name=?",r.CusName).Delete(); err != nil{
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _,err = dao.ScanSubdomain.Where("cus_name=?",r.CusName).Delete(); err != nil{
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _,err = dao.ScanPort.Where("cus_name=?",r.CusName).Delete(); err != nil{
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	if _,err = dao.ScanWeb.Where("cus_name=?",r.CusName).Delete(); err != nil{
		return errors.New(fmt.Sprintf("删除厂商失败:%s", err.Error()))
	}
	return nil
}

// SearchManager 厂商模糊搜索分页查询
func (s *serviceScan) SearchManager(page, limit int, search interface{})*model.ResAPiScanManager{
	var (
		result []*model.ScanHome
	)
	SearchModel := dao.ScanHome.Clone()
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("厂商管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanManager{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanManager{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	results := make([]model.ResAPiScanManagerInfo,0)
	for i,_:=range result{
		index++
		result[i].Id = index
		subCount,_ :=dao.ScanSubdomain.Where("cus_name=?", result[i].CusName).Count()
		portCount,_ :=dao.ScanPort.Where("cus_name=?", result[i].CusName).Count()
		urlCount,_ :=dao.ScanWeb.Where("cus_name=?", result[i].CusName).Count()
		results = append(results, model.ResAPiScanManagerInfo{
			Id: index,
			CusName: result[i].CusName,
			CusTime: result[i].CreateAt,
			CusSudDomainNum: subCount,
			CusPortNum: portCount,
			CusWebNum: urlCount,
		})
	}
	return &model.ResAPiScanManager{Code:0, Msg:"ok", Count:int64(count), Data:results}
}

// DomainAdd 添加主域名
func (s *serviceScan) DomainAdd(r *model.ScanDomainApiAddReq)error{
	count,err := dao.ScanHome.Where("cus_name=?", r.CusName).Count()
	if err != nil{
		logger.WebLog.Warningf("综合扫描-添加主域名失败:%s", err.Error())
		return errors.New("添加主域名失败,数据库错误")
	}
	if count == 0{
		return errors.New("添加主域名失败,该厂商不存在")
	}
	strList := gstr.Split(r.Domain,"\n")
	domainList := gset.NewStrSet()
	if len(strList) == 0{
		return errors.New("添加主域名失败,无有效数据")
	}
	for _,tmp := range strList{
		domain := gstr.Trim(tmp)
		if domain == ""{
			continue
		}
		if e := gvalid.Check(domain,"domain","你输入的主域名格式有误,请检查"); e != nil{ // 校检domain
			return errors.New(e.FirstString())
		}
		domainList.Add(domain)
	}
	if domainList.Size() == 0{
		return errors.New("添加主域名失败,无有效数据")
	}
	results,err := dao.ScanDomain.Where("1=?",1).FindAll()
	if err != nil{
		return errors.New("添加主域名失败,数据库查询错误")
	}
	for _,v := range results{
		if domainList.ContainsI(v.Domain){
			domainList.Remove(v.Domain)
		}
	}
	if domainList.Size() == 0{
		return errors.New("添加主域名失败,无有效数据")
	}
	logger.WebLog.Debugf("添加主域名成功，共:%d个 %+v", domainList.Size(), domainList.String())
	for _,domain := range domainList.Slice(){
		_,err = dao.ScanDomain.Insert(g.Map{
			"CusName": r.CusName,
			"Domain": domain,
			"Flag": false,
			"NsqFlag": false,
		})
		if err != nil {
			logger.WebLog.Warningf("添加主域名 插入数据库错误:%s", err.Error())
			continue
		}
	}
	go pushmsg.PushDomain(r.CusName)
	return nil
}

// SearchDomain 主域名模糊搜索分页查询
func (s *serviceScan) SearchDomain(page, limit int, search interface{})*model.ResAPiScanDomain{
	var (
		result []*model.ScanDomain
	)
	SearchModel := dao.ScanDomain.Clone()
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
		if gconv.String(j.Get("Domain")) != ""{
			SearchModel = SearchModel.Where("domain like ?", "%"+gconv.String(j.Get("Domain"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("主域名管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanDomain{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanDomain{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiScanDomain{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// GetApiCusName 返回Group厂商数据
func (s *serviceScan) GetApiCusName(page, limit int, search interface{})*model.ResAPiScanCusNames{
	var (
		result []model.ScanHome
	)
	SearchModel := dao.ScanHome.Clone()
	searchStr := gconv.String(search)
	if searchStr != ""{
		SearchModel = SearchModel.Where("cus_name like ?", "%"+searchStr+"%")
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			return &model.ResAPiScanCusNames{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanCusNames{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiScanCusNames{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// SearchSubDomain 子域名模糊搜索分页查询
func (s *serviceScan) SearchSubDomain(page, limit int, search interface{})*model.ScanSubdomainRes{
	var (
		result []*model.ScanSubdomain
	)
	SearchModel := dao.ScanSubdomain.Clone()
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
		if gconv.String(j.Get("IP")) != ""{
			SearchModel = SearchModel.Where("ip like ?", "%"+gconv.String(j.Get("IP"))+"%")
		}
		if gconv.String(j.Get("Location")) != ""{
			SearchModel = SearchModel.Where("location like ?", "%"+gconv.String(j.Get("Location"))+"%")
		}
		if gconv.String(j.Get("SubDomain")) != ""{
			SearchModel = SearchModel.Where("subdomain like ?", "%"+gconv.String(j.Get("SubDomain"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("子域名管理分页查询 数据库错误:%s", err.Error())
			return &model.ScanSubdomainRes{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ScanSubdomainRes{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ScanSubdomainRes{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// SearchPortScan 端口模糊搜索分页查询
func (s *serviceScan) SearchPortScan(page, limit int, search interface{})*model.ResAPiScanPorts{
	var (
		result []*model.ScanPort
	)
	SearchModel := dao.ScanPort.Clone()
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
		if gconv.String(j.Get("IP")) != ""{
			SearchModel = SearchModel.Where("host like ?", "%"+gconv.String(j.Get("IP"))+"%")
		}
		if gconv.String(j.Get("port")) != ""{
			SearchModel = SearchModel.Where("port = ?", gconv.String(j.Get("port")))
		}
		if gconv.String(j.Get("servicename")) != ""{
			SearchModel = SearchModel.Where("service_name like ?", "%"+gconv.String(j.Get("servicename"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("端口管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanPorts{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanPorts{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiScanPorts{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// SearchWebInfo Web信息模糊搜索分页查询
func (s *serviceScan) SearchWebInfo(page, limit int, search interface{})*model.ResAPiScanWebInfos{
	var (
		result []*model.ScanWeb
	)
	SearchModel := dao.ScanWeb.Clone()
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("CusName")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("CusName"))+"%")
		}
		if gconv.String(j.Get("url")) != ""{
			SearchModel = SearchModel.Where("url like ?", "%"+gconv.String(j.Get("url"))+"%")
		}
		if gconv.String(j.Get("title")) != ""{
			SearchModel = SearchModel.Where("title like ?", "%"+gconv.String(j.Get("title"))+"%")
		}
		if gconv.String(j.Get("banalyze")) != ""{
			SearchModel = SearchModel.Where("banalyze like ?", "%"+gconv.String(j.Get("banalyze"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("Web信息分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanWebInfos{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanWebInfos{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
		result[i].Js = ""
		result[i].Urls = ""
		result[i].Forms = ""
		result[i].Secret = ""
		result[i].Image = ""
		tmp := strings.Split(result[i].Fingerprint, "-")
		if len(tmp) > 1{
			result[i].Fingerprint = tmp[0]
		}
	}
	return &model.ResAPiScanWebInfos{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// WebInfoTree 返回web爬虫结果
func (s *serviceScan) WebInfoTree(r *model.ScanWebTreeReq)*model.ReScanWebTree{
	result,err := dao.ScanWeb.Where("url=?", r.Url).FindOne()
	if err != nil {
		return &model.ReScanWebTree{Code:201, Msg:"数据库查询错误", UrlData: nil}
	}
	if result == nil{
		return &model.ReScanWebTree{Code:201, Msg:"无结果", UrlData: nil}
	}
	var UrlData []model.ReScanWebTreeInfo
	if len(result.Urls) != 0{
		tmpList := strings.Split(result.Urls, "\n")
		for _,v := range tmpList{
			UrlData = append(UrlData, model.ReScanWebTreeInfo{Title: v, Href: v})
		}
	}
	if len(UrlData) == 0{
		UrlData = append(UrlData, model.ReScanWebTreeInfo{Title: "无数据", Href: ""})
	}
	var JsData []model.ReScanWebTreeInfo
	if len(result.Js) != 0{
		tmpList := strings.Split(result.Js, "\n")
		for _,v := range tmpList{
			JsData = append(JsData, model.ReScanWebTreeInfo{Title: v, Href: v})
		}
	}
	if len(JsData) == 0{
		JsData = append(JsData, model.ReScanWebTreeInfo{Title: "无数据", Href: ""})
	}
	var FormsData []model.ReScanWebTreeInfo
	if len(result.Forms) != 0{
		tmpList := strings.Split(result.Forms, "\n")
		for _,v := range tmpList{
			FormsData = append(FormsData, model.ReScanWebTreeInfo{Title: v, Href: v})
		}
	}
	if len(FormsData) == 0{
		FormsData = append(FormsData, model.ReScanWebTreeInfo{Title: "无数据", Href: ""})
	}
	imagePath := strings.Replace(result.Image, "public/","",-1)
	return &model.ReScanWebTree{Code:200, Msg:"ok", UrlData: UrlData, JsData: JsData, FormsData:FormsData,Secret:result.Secret,Images:"/"+imagePath}
}

// WebInfoDel 删除指定url
func (s *serviceScan) WebInfoDel(r *model.ScanWebTreeReq)error{
	_,err := dao.ScanWeb.Where("url=?",r.Url).Delete()
	if err != nil {
		logger.WebLog.Warningf("删除URL数据库错误:%s", err.Error())
		return errors.New("删除URL失败,数据库错误")
	}
	return nil
}