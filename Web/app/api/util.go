package api

import (
	"fmt"

	"Web/app/model"
	"Web/app/service"
	"Web/library/response"

	"github.com/gogf/gf/net/ghttp"
	"github.com/gogf/gf/os/gfile"
	"github.com/gogf/gf/os/gtime"
)

var Util = new(apiUtil)

type apiUtil struct{}

// AvCheck 杀软检测接口
func (a *apiUtil) AvCheck(r *ghttp.Request){
	var(
		data *model.ApiUtilAvCheckReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "杀软检测", "检测成功")
	response.JsonExit(r, 200, service.Util.AvCheck(data))
}

// SubDomainAdd 添加子域名扫描任务
func (a *apiUtil) SubDomainAdd(r *ghttp.Request){
	var(
		data *model.ApiScanDomainAddReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Util.SubDomainAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "信息收集-子域名扫描添加任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchSubDomainManager 子域名扫描管理模糊分页查询
func (a *apiUtil) SearchSubDomainManager(r *ghttp.Request){
	r.Response.WriteJson(service.Util.SearchSubDomainManager(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SearchSubDomainShow 子域名扫描详情模糊分页查询
func (a *apiUtil) SearchSubDomainShow(r *ghttp.Request){
	taskName := r.GetString("taskname")
	if taskName == ""{
		response.JsonExit(r, 201, "任务名错误")
	}
	r.Response.WriteJson(service.Util.SearchSubDomainShow(r.GetInt("page"), r.GetInt("limit"), taskName, r.Get("searchParams")))
}

// ExportSubDomainXlsx 导出子域名扫描数据
func (a *apiUtil) ExportSubDomainXlsx(r *ghttp.Request){
	taskName := r.GetString("name")
	if taskName == ""{
		response.JsonExit(r, 201, "任务名错误")
	}
	result,err := service.Util.ExportSubDomainXlsx(taskName)
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	r.Response.Header().Set("Content-Type", "application/octet-stream")
	r.Response.Header().Set("Content-Disposition", "attachment; filename="+taskName+"_子域名"+".xlsx")
	r.Response.Header().Set("Content-Transfer-Encoding", "binary")
	r.Response.WriteExit(result)
}

// SubDomainDel 子域名扫描删除指定任务数据
func (a *apiUtil) SubDomainDel(r *ghttp.Request){
	var(
		data *model.ApiUtilPortScanDelReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.Util.SubDomainDel(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "Util-子域名扫描删除任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// SubDomainEmpty 清空子域名扫描数据
func (a *apiUtil) SubDomainEmpty(r *ghttp.Request){
	if err := service.Util.SubDomainEmpty(); err != nil{
		response.JsonExit(r, 201, "清空子域名扫描数据失败,数据库错误")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "Util-子域名扫描清空数据", "清空数据成功")
		response.JsonExit(r, 200, "ok")
	}
}

// SubDomainNSqStats 子域名扫描管理 Nsqd详情
func (a *apiUtil) SubDomainNSqStats(r *ghttp.Request){
	r.Response.WriteJson(service.Util.SubDomainNSqStats())
}

// PortScanAdd 添加端口扫描任务
func (a *apiUtil) PortScanAdd(r *ghttp.Request){
	var(
		data *model.ApiUtilPortScanAddReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if result,err := service.Util.PortScanAdd(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "端口扫描添加任务", result)
		response.JsonExit(r, 200, result)
	}
}

// SearchPortManager 端口扫描管理分页查询
func (a *apiUtil) SearchPortManager(r *ghttp.Request){
	r.Response.WriteJson(service.Util.SearchPortManager(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// PortScanNSqStats 端口扫描 返回nsq信息
func (a *apiUtil) PortScanNSqStats(r *ghttp.Request){
	r.Response.WriteJson(service.Util.PortScanNSqStats())
}

// PortScanDel 删除指定任务端口扫描数据
func (a *apiUtil) PortScanDel(r *ghttp.Request){
	var(
		data *model.ApiUtilPortScanDelReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.Util.PortScanDel(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "端口扫描删除任务", fmt.Sprintf("任务名[%s]", data.CusName))
		response.JsonExit(r, 200, "ok")
	}
}

// PortScanEmpty 清空所有端口扫描数据
func (a *apiUtil) PortScanEmpty(r *ghttp.Request){
	if err := service.Util.PortScanEmpty(); err != nil{
		response.JsonExit(r, 201, "清空端口扫描数据失败,数据库错误")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "端口扫描清空数据", "清空数据成功")
		response.JsonExit(r, 200, "ok")
	}
}

// SearchPortScanShow 端口扫描详情分页查询
func (a *apiUtil) SearchPortScanShow(r *ghttp.Request){
	taskName := r.GetString("taskname")
	if taskName == ""{
		response.JsonExit(r, 201, "任务名错误")
	}
	r.Response.WriteJson(service.Util.SearchPortScanShow(r.GetInt("page"), r.GetInt("limit"), taskName, r.Get("searchParams")))
}

// ExportPortScanXlsx 导出端口扫描数据
func (a *apiUtil) ExportPortScanXlsx(r *ghttp.Request){
	taskName := r.GetString("name")
	if taskName == ""{
		response.JsonExit(r, 201, "任务名错误")
	}
	result,err := service.Util.ExportPortScanXlsx(taskName)
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	r.Response.Header().Set("Content-Type", "application/octet-stream")
	r.Response.Header().Set("Content-Disposition", "attachment; filename="+taskName+".xlsx")
	r.Response.Header().Set("Content-Transfer-Encoding", "binary")
	r.Response.WriteExit(result)
}

// PortScanEchartsInfo 端口扫描Echarts图标统计信息
func (a *apiUtil) PortScanEchartsInfo(r *ghttp.Request){
	taskName := r.GetString("taskname")
	if taskName == ""{
		response.JsonExit(r, 201, "任务名错误")
	}
	r.Response.WriteJson(service.Util.PortScanEchartsInfo(taskName))
}

// SearchBanalyzeManager web指纹管理模糊分页查询
func (a *apiUtil) SearchBanalyzeManager(r *ghttp.Request){
	r.Response.WriteJson(service.Util.SearchBanalyzeManager(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// BanalyzeEmpty 清空所有web指纹数据
func (a *apiUtil) BanalyzeEmpty(r *ghttp.Request){
	if err := service.Util.BanalyzeEmpty(); err != nil{
		response.JsonExit(r, 201, "清空web指纹数据失败,数据库错误")
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "web指纹清空数据", "清空数据成功")
		response.JsonExit(r, 200, "ok")
	}
}

// BanalyzeAdd 添加指纹
func (a *apiUtil) BanalyzeAdd(r *ghttp.Request){
	data := r.GetBodyString()
	if len(data) == 0{
		response.JsonExit(r, 201, "请提交json指纹数据")
	}
	msg,err := service.Util.BanalyzeAdd(data)
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "信息收集-添加指纹", "添加指纹成功")
	response.JsonExit(r, 200, msg)
}

// BanalyzeDelete 删除指定指纹
func (a *apiUtil) BanalyzeDelete(r *ghttp.Request){
	var(
		data *model.ApiUtilBanalyzeDeteleReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.Util.BanalyzeDelete(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "信息收集-删除指纹", fmt.Sprintf("指纹名[%s]", data.Key))
	response.JsonExit(r, 200, "ok")
}

// BanalyzeShow 查看指定指纹
func (a *apiUtil) BanalyzeShow(r *ghttp.Request){
	var(
		data *model.ApiUtilBanalyzeDeteleReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if msg,err := service.Util.BanalyzeShow(data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}else{
		response.JsonExit(r, 200, msg)
	}
}

// BanalyzeUpdate 修改指纹
func (a *apiUtil) BanalyzeUpdate(r *ghttp.Request){
	data := r.GetBodyString()
	if len(data) == 0{
		response.JsonExit(r, 201, "请提交json指纹数据")
	}
	msg,err := service.Util.BanalyzeUpdate(data)
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	response.JsonExit(r, 200, msg)
}

// BanalyzeExport 导出指纹
func (a *apiUtil) BanalyzeExport(r *ghttp.Request){
	result,err := service.Util.BanalyzeExport()
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	r.Response.Header().Set("Content-Type", "application/json")
	r.Response.Header().Set("Content-Disposition", "attachment; filename=web指纹.json")
	r.Response.WriteExit(result)
}

// BanalyzeScan 进行指纹识别
func (a *apiUtil) BanalyzeScan(r *ghttp.Request){
	r.Response.WriteJson(service.Util.BanalyzeScan(r.Get("searchParams")))
}

// BanalyzeUpload 批量上传指纹
func (a *apiUtil) BanalyzeUpload(r *ghttp.Request){
	files := r.GetUploadFile("data")
	if files == nil {
		response.JsonExit(r, 201, "指纹上传数据有误")
	}
	files.Filename = gtime.TimestampMicroStr() + ".json"
	fileName, err := files.Save(gfile.TempDir())
	if err != nil {
		response.JsonExit(r, 201, "指纹上传失败")
	}
	jsonData := gfile.GetBytes(gfile.Join(gfile.TempDir(),fileName))
	msg, err := service.Util.BanalyzeUpload(jsonData)
	if err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	response.JsonExit(r, 200, msg)
}