package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"Web/app/dao"
	"Web/app/model"
	"Web/library/logger"
	Gnsq "Web/library/nsq"
	"Web/library/nsq/producer"
	"Web/library/util/avcheck"
	"Web/library/util/banalyze"

	"github.com/360EntSecGroup-Skylar/excelize/v2"
	"github.com/gogf/gf/container/gset"
	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/text/gstr"
	"github.com/gogf/gf/util/gconv"
	"github.com/gogf/gf/util/gvalid"
	"github.com/projectdiscovery/ipranger"
)

var Util = new(serviceUtil)

type serviceUtil struct{}

// AvCheck 杀软检测
func (s *serviceUtil) AvCheck(r *model.ApiUtilAvCheckReq)string{
	if result,err := avcheck.PareAv(r.Av); err != nil{
		return err.Error()
	}else{
		return result
	}
}

// SubDomainAdd 添加子域名扫描任务
func (s *serviceUtil) SubDomainAdd(r *model.ApiScanDomainAddReq)error{
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

	// 任务信息保存到数据库中
	if result,err := dao.UtilSubdomainTask.Where("cus_name=?", r.CusName).FindOne(); err != nil{
		return errors.New("添加子域名扫描任务失败,数据库错误")
	}else if result == nil{
		if _,err = dao.UtilSubdomainTask.Insert(g.Map{"cus_name":r.CusName,"domain_num":len(domainList),"scan_num":0}); err != nil{
			return errors.New("添加子域名扫描任务失败,数据库错误")
		}
	}else{
		if _,err = dao.UtilSubdomainTask.Update(g.Map{"domain_num":result.DomainNum+len(domainList)},"cus_name", r.CusName); err != nil{
			return errors.New("添加子域名扫描任务失败,数据库错误")
		}
	}
	logger.WebLog.Debugf("Util-添加主域名成功，共:%d个 %+v", len(domainList), domainList)
	pubMessages := make([]model.NsqPushDomain,0)
	for _,k := range domainList{
		pubMessages = append(pubMessages, model.NsqPushDomain{CusName: "util-"+r.CusName, Domain: k})
	}
	go producer.PubSubDomain(pubMessages)
	return nil
}

// SearchSubDomainManager 子域名扫描管理模糊分页查询
func (s *serviceUtil) SearchSubDomainManager(page, limit int, search interface{}) *model.ResAPiUtilSubDomainManager{
	var (
		result []*model.UtilSubdomainTask
	)
	SearchModel := dao.UtilSubdomainTask.Clone() // 链式操作
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("taskname")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("taskname"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("Util-子域名扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiUtilSubDomainManager{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiUtilSubDomainManager{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiUtilSubDomainManager{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// SearchSubDomainShow 子域名扫描详情模糊分页查询
func (s *serviceUtil) SearchSubDomainShow(page, limit int, cus_name string, search interface{}) *model.ResAPiScanSubDomain{
	var (
		result []*model.ScanSubdomain
	)
	SearchModel := dao.UtilSubdomainResult.Clone() // 链式操作
	SearchModel = SearchModel.Where("cus_name=?", cus_name)
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
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
			logger.WebLog.Warningf("Util-子域名分页查询 数据库错误:%s", err.Error())
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

// ExportSubDomainXlsx 导出子域名扫描数据
func (s *serviceUtil)ExportSubDomainXlsx(TaskName string)(*bytes.Buffer, error){
	var result []model.UtilSubdomainResult
	err := dao.UtilSubdomainResult.Where("cus_name=?", TaskName).Scan(&result)
	if err != nil {
		return nil,errors.New("导出子域名扫描数据失败,数据库错误")
	}
	if len(result) == 0{
		return nil,errors.New("导出子域名扫描数据失败,该任务无数据")
	}
	xlsx := excelize.NewFile() // 新建xlsx文档
	index := xlsx.NewSheet(TaskName)  // 创建一个新工作表
	xlsx.DeleteSheet("Sheet1") // 删除默认创建的Sheet1表
	// 设置标头
	xlsx.SetCellValue(TaskName,"A1","Domain")
	xlsx.SetCellValue(TaskName,"B1","SubDomain")
	xlsx.SetCellValue(TaskName,"C1","IP")
	xlsx.SetCellValue(TaskName,"D1","CName")
	xlsx.SetCellValue(TaskName,"E1","CDN")
	xlsx.SetCellValue(TaskName,"F1","地区")
	for i, info := range result {
		xlsx.SetCellValue(TaskName, "A" + strconv.Itoa(i+2), info.Domain)
		xlsx.SetCellValue(TaskName, "B" + strconv.Itoa(i+2), info.Subdomain)
		xlsx.SetCellValue(TaskName, "C" + strconv.Itoa(i+2), info.Ip)
		xlsx.SetCellValue(TaskName, "D" + strconv.Itoa(i+2), info.Cname)
		xlsx.SetCellValue(TaskName, "E" + strconv.Itoa(i+2), info.Cdn)
		xlsx.SetCellValue(TaskName, "F" + strconv.Itoa(i+2), info.Location)
	}
	xlsx.SetColWidth(TaskName, "A", "A", 20)
	xlsx.SetColWidth(TaskName, "B", "B", 30)
	xlsx.SetColWidth(TaskName, "C", "C", 15)
	xlsx.SetColWidth(TaskName, "D", "D", 30)
	xlsx.SetColWidth(TaskName, "E", "E", 10)
	xlsx.SetColWidth(TaskName, "F", "F", 30)
	xlsx.SetActiveSheet(index) // 设置工作簿的默认工作表
	var buf bytes.Buffer
	err = xlsx.Write(&buf)
	if err != nil {
		return nil,errors.New("导出子域名扫描数据失败,xlsx流写入失败")
	}
	return &buf,nil
}

// SubDomainDel 子域名扫描删除指定任务数据
func (s *serviceUtil) SubDomainDel(r *model.ApiUtilPortScanDelReq)error{
	res,err := dao.UtilSubdomainTask.Delete("cus_name=?",r.CusName)
	if err != nil{
		return errors.New("删除该任务失败,数据库错误")
	}else if res == nil{
		return errors.New("删除该任务失败,数据库中无此任务")
	}
	dao.UtilSubdomainResult.Delete("cus_name=?", r.CusName)
	return nil
}

// SubDomainEmpty 清空子域名扫描数据
func (s *serviceUtil) SubDomainEmpty()error{
	if _,err := dao.UtilSubdomainTask.Delete("1=1"); err != nil{
		logger.WebLog.Warningf("清空Util-子域名扫描数据 数据库错误:%s", err.Error())
		return errors.New("清空子域名数据失败,数据库错误")
	}
	if _,err := dao.UtilSubdomainResult.Delete("1=1"); err != nil{
		logger.WebLog.Warningf("清空util-子域名扫描数据 数据库错误:%s", err.Error())
		return errors.New("清空子域名数据失败,数据库错误")
	}
	return nil
}

// SubDomainNSqStats 子域名扫描管理 Nsqd详情
func (s *serviceUtil) SubDomainNSqStats()*model.ResAPiPortScanNsq{
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

// PortScanAdd 添加端口扫描任务
func (s *serviceUtil) PortScanAdd(r *model.ApiUtilPortScanAddReq) (string,error) {
	// 检测待扫描端口 参数值是否正确
	if r.Ports!= "full" && r.Ports!= "top100" && r.Ports!="top1000" && !strings.Contains(r.Ports, "-") &&
		!strings.Contains(r.Ports, ",") && !gstr.IsNumeric(r.Ports){
		return "", errors.New("待扫描端口ports参数格式错误,请检查")
	}

	// 解析hosts参数值
	hostlist := strings.Split(r.Hosts,"\n")
	IpSet := gset.NewStrSet() // 保存解析的host并去重
	// 提取解析host
	if len(hostlist) == 1{ // 单条记录
		if !ipranger.IsCidr(r.Hosts) && !ipranger.IsIP(r.Hosts){ // 判断提交的host格式是否正确
			return "",errors.New("提交的主机地址格式有误,请检查")
		}else if ipranger.IsIP(r.Hosts){
			IpSet.Add(gstr.Trim(r.Hosts))
		}else{
			iplist,err := ipranger.Ips(r.Hosts)
			if err != nil {
				return "",errors.New("提交的主机地址格式有误,请检查")
			}else{
				IpSet.Add(iplist...)
			}
		}
	}else{ // 多条记录
		for _,tmphost := range hostlist{
			if gstr.Trim(tmphost) == ""{
				continue
			}
			if !ipranger.IsCidr(tmphost) && !ipranger.IsIP(tmphost){
				return "",errors.New("提交的主机地址格式有误,请检查")
			}else if ipranger.IsIP(tmphost){
				IpSet.Add(gstr.Trim(tmphost))
			}else{
				iplist,err := ipranger.Ips(tmphost)
				if err != nil {
					return "",errors.New("提交的主机地址格式有误,请检查")
				}else{
					IpSet.Add(iplist...)
				}
			}
		}
	}

	if IpSet.Size() == 0{
		return "",errors.New("解析后的host主机数为0个,请检查")
	}

	// 任务信息保存到数据库中
	if result,err := dao.UtilPortscanTask.Where("cus_name=?", r.CusName).FindOne(); err != nil{
		return "",errors.New("添加端口扫描任务失败,数据库错误")
	}else if result == nil{
		if result,err := dao.UtilPortscanTask.Insert(g.Map{"cus_name":r.CusName,"host_num":IpSet.Size(),"scan_num":0}); err != nil{
			return "",errors.New("添加端口扫描任务失败,数据库错误")
		}else if result == nil{
			return "",errors.New("添加端口扫描任务失败,数据库插入数据失败")
		}
	}else{
		if res,err := dao.UtilPortscanTask.Update(g.Map{"host_num":result.HostNum+IpSet.Size()},"cus_name", r.CusName); err != nil{
			return "",errors.New("添加端口扫描任务失败,数据库错误")
		}else if res == nil{
			return "",errors.New("添加端口扫描任务失败,数据库更新数据失败")
		}
	}

	logger.WebLog.Debugf("util-添加端口扫描任务[%s]成功, 共计[%d]台主机",r.CusName, IpSet.Size())
	// 批量发送到消息队列中
	SendMsg := make([]model.ApiUtilPortScanAddReq, 0)

	r.CusName = "util-"+r.CusName
	for _,addres := range IpSet.Slice(){
		tmpmsg := *r
		tmpmsg.Hosts = addres
		SendMsg = append(SendMsg, tmpmsg)
	}
	// 异步投递消息
	go producer.PortScanSendMessage(SendMsg)
	return fmt.Sprintf("util-添加端口扫描任务成功,共计:%d台主机", IpSet.Size()),nil
}

// SearchPortManager 端口扫描管理模糊分页查询
func (s *serviceUtil) SearchPortManager(page, limit int, search interface{}) *model.ResAPiUtilPortScanManager{
	var (
		result []*model.UtilPortscanTask
	)
	SearchModel := dao.UtilPortscanTask.Clone() // 链式操作
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("cusname")) != ""{
			SearchModel = SearchModel.Where("cus_name like ?", "%"+gconv.String(j.Get("cusname"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("端口扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiUtilPortScanManager{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiUtilPortScanManager{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiUtilPortScanManager{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// PortScanNSqStats 端口扫描管理 Nsqd详情
func (s *serviceUtil) PortScanNSqStats()*model.ResAPiPortScanNsq{
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

// PortScanDel 端口扫描删除指定任务数据
func (s *serviceUtil) PortScanDel(r *model.ApiUtilPortScanDelReq)error{
	res,err := dao.UtilPortscanTask.Delete("cus_name=?",r.CusName)
	if err != nil{
		return errors.New("删除该任务失败,数据库错误")
	}else if res == nil{
		return errors.New("删除该任务失败,数据库中无此任务")
	}
	dao.UtilPortscanResult.Delete("cus_name=?", r.CusName)
	return nil
}

// PortScanEmpty 清空端口扫描数据
func (s *serviceUtil) PortScanEmpty()error{
	if _,err := dao.UtilPortscanTask.Delete("1=1"); err != nil{
		logger.WebLog.Warningf("清空util-端口扫描数据 数据库错误:%s", err.Error())
		return err
	}
	if _,err := dao.UtilPortscanResult.Delete("1=1"); err != nil{
		logger.WebLog.Warningf("清空util-端口扫描数据 数据库错误:%s", err.Error())
		return err
	}
	return nil
}

// SearchPortScanShow 端口扫描详情模糊分页查询
func (s *serviceUtil)SearchPortScanShow(page, limit int, task_name string ,search interface{}) *model.ResAPiUtilPortScanShow{
	var (
		result []*model.UtilPortscanResult
	)
	SearchModel := dao.UtilPortscanResult.Clone() // 链式操作
	SearchModel = SearchModel.Where("cus_name=?", task_name)
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("host")) != ""{
			SearchModel = SearchModel.Where("host like ?", "%"+gconv.String(j.Get("host"))+"%")
		}
		if gconv.String(j.Get("port")) != ""{
			SearchModel = SearchModel.Where("port = ?", gconv.String(j.Get("port")))
		}
		if gconv.String(j.Get("servicename")) != ""{
			SearchModel = SearchModel.Where("service_name like ?", "%"+gconv.String(j.Get("servicename"))+"%")
		}
		if gconv.String(j.Get("title")) != ""{
			SearchModel = SearchModel.Where("title like ?", "%"+gconv.String(j.Get("title"))+"%")
		}
		if gconv.String(j.Get("url")) != ""{
			SearchModel = SearchModel.Where("url like ?", "%"+gconv.String(j.Get("url"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("端口扫描管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiUtilPortScanShow{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiUtilPortScanShow{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiUtilPortScanShow{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// ExportPortScanXlsx 导出端口扫描数据
func (s *serviceUtil)ExportPortScanXlsx(TaskName string)(*bytes.Buffer, error){
	var result []model.UtilPortscanResult
	err := dao.UtilPortscanResult.Where("cus_name=?", TaskName).Scan(&result)
	if err != nil {
		return &bytes.Buffer{},errors.New("导出端口扫描数据失败,数据库错误")
	}
	if len(result) == 0{
		return &bytes.Buffer{},errors.New("导出端口扫描数据失败,该任务无数据")
	}
	xlsx := excelize.NewFile() // 新建xlsx文档
	index := xlsx.NewSheet(TaskName)  // 创建一个新工作表
	xlsx.DeleteSheet("Sheet1") // 删除默认创建的Sheet1表
	// 设置标头
	xlsx.SetCellValue(TaskName,"A1","Host")
	xlsx.SetCellValue(TaskName,"B1","Port")
	xlsx.SetCellValue(TaskName,"C1","ServerName")
	xlsx.SetCellValue(TaskName,"D1","Product")
	xlsx.SetCellValue(TaskName,"E1","Version")
	xlsx.SetCellValue(TaskName,"F1","Url")
	xlsx.SetCellValue(TaskName,"G1","Code")
	xlsx.SetCellValue(TaskName,"H1","Title")
	for i, info := range result {
		xlsx.SetCellValue(TaskName, "A" + strconv.Itoa(i+2), info.Host)
		xlsx.SetCellValue(TaskName, "B" + strconv.Itoa(i+2), info.Port)
		xlsx.SetCellValue(TaskName, "C" + strconv.Itoa(i+2), info.ServiceName)
		xlsx.SetCellValue(TaskName, "D" + strconv.Itoa(i+2), info.VendorProduct)
		xlsx.SetCellValue(TaskName, "E" + strconv.Itoa(i+2), info.Version)
		xlsx.SetCellValue(TaskName, "F" + strconv.Itoa(i+2), info.Url)
		xlsx.SetCellValue(TaskName, "G" + strconv.Itoa(i+2), info.Code)
		xlsx.SetCellValue(TaskName, "H" + strconv.Itoa(i+2), info.Title)
	}
	xlsx.SetColWidth(TaskName, "A", "A", 20)
	xlsx.SetColWidth(TaskName, "B", "B", 12)
	xlsx.SetColWidth(TaskName, "C", "C", 15)
	xlsx.SetColWidth(TaskName, "D", "D", 25)
	xlsx.SetColWidth(TaskName, "E", "E", 13)
	xlsx.SetColWidth(TaskName, "F", "F", 28)
	xlsx.SetColWidth(TaskName, "G", "G", 11)
	xlsx.SetColWidth(TaskName, "H", "H", 35)
	xlsx.SetActiveSheet(index) // 设置工作簿的默认工作表
	var buf bytes.Buffer
	err = xlsx.Write(&buf)
	if err != nil {
		return &bytes.Buffer{},errors.New("导出端口扫描数据失败,xlsx流写入失败")
	}
	return &buf,nil
}

// PortScanEchartsInfo 端口扫描Echarts图标统计信息
func (s *serviceUtil) PortScanEchartsInfo(TaskName string) *model.ResApiUtilPortScanEchartsInfo{
	var result1 []model.ResApiUtilPortScanEchartsInfos
	var result2 []model.ResApiUtilPortScanEchartsInfos1
	err := dao.UtilPortscanResult.Fields("COUNT(service_name) Number, service_name").
		Where("cus_name=?", TaskName).Group("service_name").Limit(10).Scan(&result1)
	if err != nil {
		return nil
	}
	err = dao.UtilPortscanResult.Fields("COUNT(port) Number, port").
		Where("cus_name=?", TaskName).Group("port").Limit(10).Scan(&result2)
	if err != nil {
		return nil
	}
	return &model.ResApiUtilPortScanEchartsInfo{Code:200,Msg:"ok",Data:result1, Data1:result2}
}

// SearchBanalyzeManager web指纹管理模糊分页查询
func (s *serviceUtil) SearchBanalyzeManager(page, limit int, search interface{}) *model.ResAPiUtilBanalyzeManager{
	var (
		result []*model.Banalyze
	)
	SearchModel := dao.Banalyze.Clone() // 链式操作
	searchStr := gconv.String(search)
	if search != ""{
		j := gjson.New(searchStr)
		if gconv.String(j.Get("key")) != ""{
			SearchModel = SearchModel.Where("key like ?", "%"+gconv.String(j.Get("key"))+"%")
		}
		if gconv.String(j.Get("description")) != ""{
			SearchModel = SearchModel.Where("description like ?", "%"+gconv.String(j.Get("description"))+"%")
		}
	}
	count,_ := SearchModel.Count()
	if page > 0 && limit > 0 {
		err := SearchModel.Order("id desc").Limit((page-1)*limit,limit).Scan(&result)
		if err != nil {
			logger.WebLog.Warningf("web指纹管理分页查询 数据库错误:%s", err.Error())
			return &model.ResAPiUtilBanalyzeManager{Code:201, Msg:"查询失败,数据库错误", Count:0, Data:nil}
		}
	}else{
		return &model.ResAPiUtilBanalyzeManager{Code:201, Msg:"查询失败,分页参数有误", Count:0, Data:nil}
	}
	index := (page-1)*limit
	for i,_:=range result{
		index++
		result[i].Id = index
	}
	return &model.ResAPiUtilBanalyzeManager{Code:0, Msg:"ok", Count:int64(count), Data:result}
}

// BanalyzeEmpty 清空所有web指纹数据
func (s *serviceUtil) BanalyzeEmpty()error{
	if _,err := dao.Banalyze.Delete("1=1"); err != nil{
		logger.WebLog.Warningf("清空web指纹失败 数据库错误:%s", err.Error())
		return err
	}
	return nil
}

// BanalyzeAdd 添加指纹
func (s *serviceUtil) BanalyzeAdd(r string)(string,error){
	Wappalyzer,err := banalyze.LoadApps([]byte(r))
	if err != nil {
		logger.WebLog.Warningf("指纹json数据解析失败:%s", err.Error())
		return "",errors.New("JSON数据解析失败,请检查")
	}
	if len(Wappalyzer.Apps) != 1{
		return "", errors.New("只允许提交单条指纹")
	}
	banalyzeName := Wappalyzer.Apps[0].Name
	banalyzeWebsite := Wappalyzer.Apps[0].Website
	banalyzeDescription := Wappalyzer.Apps[0].Description
	if strings.Trim(banalyzeName," ") == "" || strings.Trim(banalyzeWebsite," ") == "" || strings.Trim(banalyzeDescription," ") == ""{
		return "", errors.New("缺少必须参数字段,请检查")
	}
	count,err := dao.Banalyze.Where("key=?", banalyzeName).Count()
	if err != nil {
		return "",errors.New("数据库查询错误")
	}
	if count > 0{
		return "",errors.New("该指纹名数据库已存在,请更换指纹名")
	}
	result,err := Wappalyzer.Analyze(banalyzeWebsite, 10)
	if err != nil {
		return "",errors.New("指纹识别错误,请检查url是否能访问等问题")
	}
	if len(result) == 0{
		return "",errors.New("指纹识别无匹配结果,请检查")
	}
	_,err = dao.Banalyze.Insert(g.Map{"key":banalyzeName,"description":banalyzeDescription,"value":r})
	if err != nil {
		return "",errors.New("指纹识别成功,但插入到数据库失败")
	}
	mjson,err := json.Marshal(result)
	if err != nil {
		return "",errors.New("指纹识别成功,json序列化失败")
	}
	msg := fmt.Sprintf("指纹识别成功:\n%s",string(mjson))
	return msg,nil
}

// BanalyzeDelete 删除指定指纹
func (s *serviceUtil) BanalyzeDelete(r *model.ApiUtilBanalyzeDeteleReq)error{
	_,err := dao.Banalyze.Delete(g.Map{"key":r.Key})
	if err != nil{
		return err
	}else{
		return nil
	}
}

// BanalyzeShow 查看指定指纹
func (s *serviceUtil) BanalyzeShow(r *model.ApiUtilBanalyzeDeteleReq)(string,error){
	result,err := dao.Banalyze.Where("key=?", r.Key).FindOne()
	if err != nil{
		return "",err
	}
	return result.Value, nil
}

// BanalyzeUpdate 修改指纹
func (s *serviceUtil) BanalyzeUpdate(r string)(string,error){
	Wappalyzer,err := banalyze.LoadApps([]byte(r))
	if err != nil {
		logger.WebLog.Warningf("指纹json数据解析失败:%s", err.Error())
		return "",errors.New("JSON数据解析失败,请检查")
	}
	if len(Wappalyzer.Apps) != 1{
		return "", errors.New("只允许提交单条指纹")
	}
	banalyzeName := Wappalyzer.Apps[0].Name
	banalyzeWebsite := Wappalyzer.Apps[0].Website
	banalyzeDescription := Wappalyzer.Apps[0].Description
	if strings.Trim(banalyzeName," ") == "" || strings.Trim(banalyzeWebsite," ") == "" || strings.Trim(banalyzeDescription," ") == ""{
		return "", errors.New("缺少必须参数字段,请检查")
	}
	count,err := dao.Banalyze.Where("key=?", banalyzeName).Count()
	if err != nil {
		return "",errors.New("数据库查询错误")
	}
	if count == 0 {
		return "",errors.New("该指纹名数据库不存在，请检查")
	}
	result,err := Wappalyzer.Analyze(banalyzeWebsite, 10)
	if err != nil {
		return "",errors.New("指纹识别错误,请检查url是否能访问等问题")
	}
	if len(result) == 0{
		return "",errors.New("指纹识别无匹配结果,请检查")
	}
	_,err = dao.Banalyze.Update(g.Map{"description":banalyzeDescription,"value":r},"key", banalyzeName)
	if err != nil {
		return "",errors.New("指纹识别成功,但更新数据失败")
	}
	mjson,err := json.Marshal(result)
	if err != nil {
		return "",errors.New("指纹识别成功,json序列化失败")
	}
	msg := fmt.Sprintf("指纹识别成功:\n%s",string(mjson))
	return msg,nil
}

// BanalyzeExport 导出指纹
func (s *serviceUtil) BanalyzeExport()(*bytes.Buffer, error){
	result,err := dao.Banalyze.Where("1=?",1).FindAll()
	if err != nil{
		return nil,err
	}
	var exportData []*banalyze.App
	for _,v := range result{
		jsonList,err := banalyze.LoadApps([]byte(v.Value))
		if err != nil{
			continue
		}
		exportData = append(exportData, jsonList.Apps[0])
	}
	data, err := json.Marshal(exportData)
	if err != nil{
		return nil,err
	}
	return bytes.NewBuffer(data),nil
}

// BanalyzeScan 进行指纹识别
func (s *serviceUtil) BanalyzeScan(search interface{}) *model.ResAPiUtilBanalyzeInfo{
	searchStr := gconv.String(search)
	if searchStr == ""{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"请提交URL进行指纹识别", Count:0, Data:nil}
	}
	j := gjson.New(searchStr)
	if gconv.String(j.Get("url")) == ""{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"请提交URL进行指纹识别", Count:0, Data:nil}
	}
	url := gconv.String(j.Get("url"))
	result,err := dao.Banalyze.Where("1=?",1).FindAll()
	if err != nil{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"指纹识别失败,数据库查询指纹错误", Count:0, Data:nil}
	}
	var exportData []*banalyze.App
	for _,v := range result{
		jsonList,err := banalyze.LoadApps([]byte(v.Value))
		if err != nil{
			continue
		}
		exportData = append(exportData, jsonList.Apps[0])
	}
	if len(exportData) == 0{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"指纹识别失败,无有效指纹库", Count:0, Data:nil}
	}
	data, err := json.Marshal(exportData)
	if err != nil{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"指纹识别失败,json序列化失败", Count:0, Data:nil}
	}
	Wappalyzer,err := banalyze.LoadApps(data)
	if err != nil{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"指纹识别失败,JSON反序列化失败", Count:0, Data:nil}
	}
	result1,err := Wappalyzer.Analyze(url, 10)
	if err != nil{
		return &model.ResAPiUtilBanalyzeInfo{Code:201, Msg:"指纹识别失败,请检查url是否能访问", Count:0, Data:nil}
	}
	var resultData []*model.ResultApp
	index := 1
	for _,v := range result1{
		resultData = append(resultData, &model.ResultApp{
			Id: index,
			Name: v.Name,
			Version: strings.Join(v.Version, "\n"),
			Implies: strings.Join(v.Implies, ","),
			Description: v.Description,
		})
		index++
	}
	return &model.ResAPiUtilBanalyzeInfo{Code:0, Msg:"ok", Count:int64(len(result1)), Data:resultData}
}

// BanalyzeUpload 批量上传指纹
func (s *serviceUtil) BanalyzeUpload(r []byte)(string,error){
	Wappalyzer,err := banalyze.LoadApps(r)
	if err != nil{
		return "", errors.New("json数据有误，指纹加载失败")
	}
	var resultData []*model.ApiUtilBanalyzeAddReq
	for _,v := range Wappalyzer.Apps{
		datastr, err := json.Marshal([]*banalyze.App{v})
		if err != nil{
			continue
		}
		resultData = append(resultData, &model.ApiUtilBanalyzeAddReq{
			Key: v.Name,
			Description: v.Description,
			Value: string(datastr),
		})
	}
	if len(resultData) == 0{
		return "", errors.New("指纹数据解析后为空，指纹加载失败")
	}
	_,err = dao.Banalyze.Insert(resultData)
	if err != nil{
		return "", errors.New("指纹导入失败,可能是导入的数据在数据库中已存在")
	}
	return "指纹导入成功", nil
}