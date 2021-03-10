package api

import (
	"fmt"

	"github.com/CTF-MissFeng/GoScan/Web/app/model"
	"github.com/CTF-MissFeng/GoScan/Web/app/service"
	"github.com/CTF-MissFeng/GoScan/Web/library/response"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/util/gconv"
)

var Scan = new(apiScan)

type apiScan struct{}

// APIKeyEngineNsqAdd 扫描引擎 添加nsq地址
func (a *apiScan) APIKeyEngineNsqAdd (r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var (
		data  *model.APIKeyEngineNsqReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.APIKeyEngineNsqAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "扫描引擎", fmt.Sprintf("修改消息队列[%s]", data.NsqHost))
		response.JsonExit(r, 200, "ok")
	}
}

// ApiKeyEnginePortScanAdd 扫描引擎 添加端口扫描
func (a *apiScan) ApiKeyEnginePortScanAdd (r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var (
		data  *model.ApiKeyEnginePortScanReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ApiKeyEnginePortScanAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改端口扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}

// ApiKeyEngineDomainAdd 扫描引擎 添加子域名
func (a *apiScan) ApiKeyEngineDomainAdd (r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var (
		data  *model.ApiKeyEngineDomainReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ApiKeyEngineDomainAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改子域名扫描参数")
		response.JsonExit(r, 200, "ok")
	}
}

// ApiKeyEngineKeyAdd 扫描引擎 添加API秘钥
func (a *apiScan) ApiKeyEngineKeyAdd (r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var (
		data  *model.ApiKeyEngineKeyReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ApiKeyEngineKeyAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改API秘钥参数")
		response.JsonExit(r, 200, "ok")
	}
}

// ApiKeyEngineWebInfoAdd 扫描引擎 添加Web探测
func (a *apiScan) ApiKeyEngineWebInfoAdd (r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var (
		data  *model.ApiKeyEngineWebInfoReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ApiKeyEngineWebInfoAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "扫描引擎", "修改Web探测参数")
		response.JsonExit(r, 200, "ok")
	}
}

// GetApiKeyEngine 扫描引擎 输出配置 客户端同步，需要传入密码
func (a *apiScan) GetApiKeyEngine (r *ghttp.Request){
	pwd := gconv.String(r.Get("pwd"))
	if pwd == "" {
		response.JsonExit(r, 201, "请输入密码")
	}
	password := g.Cfg().GetString("server.Password")
	if password == ""{
		response.JsonExit(r, 201, "Web未配置同步密码")
	}
	if pwd == password {
		r.Response.WriteJson(service.Scan.GetApiKeyEngine())
	}else{
		response.JsonExit(r, 201, "密码错误")
	}
}

// GetApiKeyEngineInfo 扫描引擎 输出配置
func (a *apiScan) GetApiKeyEngineInfo (r *ghttp.Request){
	r.Response.WriteJson(service.Scan.GetApiKeyEngine())
}

// EmptyPort 端口扫描清空消息队列
func (a *apiScan) EmptyPort(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	if err := service.Scan.EmptyPort(); err != nil{
		response.JsonExit(r, 201, "清空端口扫描任务队列失败")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "端口扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyDomain 子域名清空消息队列
func (a *apiScan) EmptyDomain(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	if err := service.Scan.EmptyDomain(); err != nil{
		response.JsonExit(r, 201, "清空子域名扫描任务队列失败")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "子域名扫描", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// EmptyWebInfo Web探测清空消息队列
func (a *apiScan) EmptyWebInfo(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	if err := service.Scan.EmptyWebInfo(); err != nil{
		response.JsonExit(r, 201, "清空Web探测任务队列失败")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "Web探测", "清空消息队列成功")
		response.JsonExit(r, 200, "ok")
	}
}

// ManagerAdd 添加厂商
func (a *apiScan) ManagerAdd(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var(
		data *model.ApiScanManagerAddReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ManagerAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "添加厂商", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// ManagerDelete 删除厂商
func (a *apiScan) ManagerDelete(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var(
		data *model.ApiScanManagerDeleteReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.ManagerDelete(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "删除厂商", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchManager 厂商模糊搜索分页查询
func (a *apiScan) SearchManager(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.SearchManager(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// DomainAdd 添加主域名
func (a *apiScan) DomainAdd(r *ghttp.Request){
	service.Text.IsUserText(r,r.Context())
	var(
		data *model.ScanDomainApiAddReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.DomainAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "添加主域名", fmt.Sprintf("厂商名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchDomain 主域名模糊搜索分页查询
func (a *apiScan) SearchDomain(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.SearchDomain(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// GetApiCusName 返回厂商数据
func (a *apiScan) GetApiCusName(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.GetApiCusName(r.GetInt("page"), r.GetInt("limit"), r.Get("cusname")))
}

// SearchSubDomain 子域名模糊搜索分页查询
func (a *apiScan) SearchSubDomain(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.SearchSubDomain(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SearchPortScan 端口模糊搜索分页查询
func (a *apiScan) SearchPortScan(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.SearchPortScan(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SearchWebInfo Web信息模糊搜索分页查询
func (a *apiScan) SearchWebInfo(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.SearchWebInfo(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// PortNSqStats 端口扫描管理 Nsqd详情
func (a *apiScan) PortNSqStats(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.PortNSqStats())
}

// DomainNSqStats 子域名扫描管理 Nsqd详情
func (a *apiScan) DomainNSqStats(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.DomainNSqStats())
}

// WebInfoNSqStats Web探测管理 Nsqd详情
func (a *apiScan) WebInfoNSqStats(r *ghttp.Request){
	r.Response.WriteJson(service.Scan.WebInfoNSqStats())
}

// WebInfoTree 返回web爬虫结果
func (a *apiScan) WebInfoTree(r *ghttp.Request){
	var data *model.ScanWebTreeReq
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	r.Response.WriteJson(service.Scan.WebInfoTree(data))
}

// WebInfoDel 删除指定url
func (a *apiScan) WebInfoDel(r *ghttp.Request){
	var data *model.ScanWebTreeReq
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Scan.WebInfoDel(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "删除web资产", fmt.Sprintf("Url[%s]", data.Url))
		response.JsonExit(r, 200, "ok")
	}
}