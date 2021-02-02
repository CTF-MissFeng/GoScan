package service

import (
	"errors"
	"time"

	"Web/app/dao"
	"Web/app/model"
	"Web/library/logger"
	Gnsq "Web/library/nsq"
	"Web/library/nsq/producer"
	"Web/library/util/icp"

	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/text/gstr"
	"github.com/gogf/gf/util/gconv"
	"github.com/gogf/gf/util/gvalid"
)

var Scan = new(serviceScan)

type serviceScan struct{}

// ManagerAdd 添加厂商
func (s *serviceScan) ManagerAdd(r *model.ApiScanManagerAddReq)error{
	count,err := dao.ScanHome.Where("cus_name=?", r.CusName).Count()
	if err != nil{
		return errors.New("添加厂商失败,数据库错误")
	}
	if count > 0{
		return errors.New("添加厂商失败,已存在该厂商")
	}
	_,err = dao.ScanHome.Insert(r)
	if err != nil{
		return errors.New("添加厂商失败,数据库错误")
	}
	return nil
}

// SearchManager 厂商模糊搜索分页查询
func (s *serviceScan) SearchManager(page, limit int, search interface{})*model.ResAPiScanManager{
	var (
		result []*model.ScanHome
	)
	SearchModel := dao.ScanHome.Clone() // 链式操作
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
		results = append(results, model.ResAPiScanManagerInfo{
			Id: index,
			CusName: result[i].CusName,
			CusTime: result[i].CreateAt,
		})
	}
	return &model.ResAPiScanManager{Code:0, Msg:"ok", Count:int64(count), Data:results}
}

// DomainAdd 添加主域名
func (s *serviceScan) DomainAdd(r *model.ApiScanDomainAddReq)error{
	count,err := dao.ScanHome.Where("cus_name=?", r.CusName).Count()
	if err != nil{
		return errors.New("添加主域名失败,数据库错误")
	}
	if count == 0{
		return errors.New("添加主域名失败,该厂商不存在")
	}
	strList := gstr.Split(r.Domain,"\n")
	domainList := make([]string,0)
	if len(strList) == 0{
		return errors.New("添加主域名失败,无有效数据")
	}else{
		for _,tmp := range strList{
			domain := gstr.Trim(tmp)
			if domain == ""{
				continue
			}
			if e := gvalid.Check(domain,"domain","你输入的主域名格式有误,请检查"); e != nil{ // 校检domain
				return errors.New(e.FirstString())
			}
			domainList = append(domainList, domain)
		}
	}
	if len(domainList) == 0{
		return errors.New("添加主域名失败,无有效数据")
	}
	logger.WebLog.Debugf("添加主域名成功，共:%d个 %+v", len(domainList), domainList)
	go icp.InsertDomain(r.CusName,domainList)
	return nil
}

// SearchDomain 主域名模糊搜索分页查询
func (s *serviceScan) SearchDomain(page, limit int, search interface{})*model.ResAPiScanDomain{
	var (
		result []*model.ScanDomain
	)
	SearchModel := dao.ScanDomain.Clone() // 链式操作
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

// APIKeyEngineNsqAdd 扫描引擎 添加nsq地址
func (s *serviceScan) APIKeyEngineNsqAdd(r *model.APIKeyEngineNsqReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_nsq").Count()
	if err != nil {
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_nsq"); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_nsq","value":jsonstr}); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEnginePortScanAdd 扫描引擎 添加端口扫描
func (s *serviceScan) ApiKeyEnginePortScanAdd(r *model.ApiKeyEnginePortScanReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_portscan").Count()
	if err != nil {
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_portscan"); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_portscan","value":jsonstr}); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEngineDomainAdd 扫描引擎 添加子域名
func (s *serviceScan) ApiKeyEngineDomainAdd(r *model.ApiKeyEngineDomainReq) error {
	count,err := dao.ApiKey.Where("key=?", "engine_domain").Count()
	if err != nil {
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_domain"); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_domain","value":jsonstr}); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}
	return nil
}

// ApiKeyEngineKeyAdd 扫描引擎 添加API秘钥
func (s *serviceScan) ApiKeyEngineKeyAdd(r *model.ApiKeyEngineKeyReq)error{
	count,err := dao.ApiKey.Where("key=?", "engine_apikey").Count()
	if err != nil {
		return errors.New("保存失败,数据库错误")
	}
	jsonstr,err := gjson.New(r).ToJsonString()
	if err != nil {
		return errors.New("保存失败,json序列化失败")
	}
	if count != 0{
		if _,err := dao.ApiKey.Update(g.Map{"value":jsonstr}, "key","engine_apikey"); err != nil{
			return errors.New("保存失败,数据库错误")
		}
	}else{
		if _,err := dao.ApiKey.Insert(g.Map{"key":"engine_apikey","value":jsonstr}); err != nil{
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
				result.ApiKey = structs
			}
		}
	}
	return &result
}

// GetApiCusName 返回Group厂商数据
func (s *serviceScan) GetApiCusName(page, limit int, search interface{})*model.ResAPiScanCusNames{
	var (
		result []model.ScanHome
	)
	SearchModel := dao.ScanHome.Clone() // 链式操作
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
func (s *serviceScan) SearchSubDomain(page, limit int, search interface{})*model.ResAPiScanSubDomain{
	var (
		result []*model.ScanSubdomain
	)
	SearchModel := dao.ScanSubdomain.Clone() // 链式操作
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
			logger.WebLog.Warningf("主域名管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiScanSubDomain{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiScanSubDomain{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiScanSubDomain{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// SearchPortScan 端口模糊搜索分页查询
func (s *serviceScan) SearchPortScan(page, limit int, search interface{})*model.ResAPiScanPorts{
	var (
		result []*model.ScanPort
	)
	SearchModel := dao.ScanPort.Clone() // 链式操作
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

// PortNSqStats 端口扫描管理 Nsqd详情
func (s *serviceScan) PortNSqStats()*model.ResAPiPortScanNsq{
	jsondata, err := producer.NsqStatsInfo(Gnsq.PortScanTopic)
	if err != nil {
		return &model.ResAPiPortScanNsq{Code:0,Msg:"获取nsq消息队列信息失败",Count:0,Data:nil}
	}
	message_count := 0 // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0 // 客户端数
	timeout_count := 0 // 超时数
	result := make([]model.ResAPiPortScanNsqInfo, 0)
	for _, v := range jsondata.Topics{
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels{
			if k.ChannelName == Gnsq.PortScanTopicChanl{
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients{
					result = append(result, model.ResAPiPortScanNsqInfo{
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
		return &model.ResAPiPortScanNsq{Code:0,Msg:"无客户端",Count:0,Data:nil,MessageCount: message_count,
			MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
	}
	return &model.ResAPiPortScanNsq{Code:0,Msg:"ok",Count:0,Data:result,MessageCount: message_count,
		MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
}

// DomainNSqStats 端口扫描管理 Nsqd详情
func (s *serviceScan) DomainNSqStats()*model.ResAPiPortScanNsq{
	jsondata, err := producer.NsqStatsInfo(Gnsq.SubDomainTopic)
	if err != nil {
		return &model.ResAPiPortScanNsq{Code:0,Msg:"获取nsq消息队列信息失败",Count:0,Data:nil}
	}
	message_count := 0 // 消息总数
	message_bytes := "" // 消息大小
	client_count := 0 // 客户端数
	timeout_count := 0 // 超时数
	result := make([]model.ResAPiPortScanNsqInfo, 0)
	for _, v := range jsondata.Topics{
		message_count = v.MessageCount
		message_bytes = gfile.FormatSize(v.MessageBytes)
		for _, k := range v.Channels{
			if k.ChannelName == Gnsq.SubDomainChanl{
				client_count = k.ClientCount
				timeout_count = k.TimeoutCount
				for _, y := range k.Clients{
					result = append(result, model.ResAPiPortScanNsqInfo{
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
		return &model.ResAPiPortScanNsq{Code:0,Msg:"无客户端",Count:0,Data:nil,MessageCount: message_count,
			MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
	}
	return &model.ResAPiPortScanNsq{Code:0,Msg:"ok",Count:0,Data:result,MessageCount: message_count,
		MessageBytes: message_bytes,TimeoutCount:timeout_count, ClientCount:client_count}
}

// EmptyPort 端口扫描清空消息队列
func (s *serviceScan) EmptyPort() error {
	return producer.NsqTopicEmpty(Gnsq.PortScanTopic, Gnsq.PortScanTopicChanl)
}

// EmptyDomain 子域名清空消息队列
func (s *serviceScan) EmptyDomain() error {
	return producer.NsqTopicEmpty(Gnsq.SubDomainTopic, Gnsq.SubDomainChanl)
}