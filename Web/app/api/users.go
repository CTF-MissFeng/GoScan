package api

import (
	"fmt"

	"Web/app/model"
	"Web/app/service"
	"Web/library/response"

	"github.com/gogf/gf/net/ghttp"
)

var Users = new(apiUser)

type apiUser struct{}

// Register 添加用户接口
func (a *apiUser) Register(r *ghttp.Request) {
	var (
		data *model.ApiUserRegisterReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.Register(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "添加用户", fmt.Sprintf("添加[%s]用户", data.Username))
		response.JsonExit(r, 200, "ok")
	}
}

// UserInfo 获取用户信息接口
func (a *apiUser) UserInfo(r *ghttp.Request) {
	response.JsonExit(r, 200, "ok", service.User.UserInfo(r.Context()))
}

// UserDel 删除用户接口
func (a *apiUser) UserDel(r *ghttp.Request){
	var(
		data *model.ApiUserDelReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.UserDel(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "删除用户", fmt.Sprintf("删除[%s]用户", data.Username))
		response.JsonExit(r, 200, "ok")
	}
}

// ChangePassword 用户修改密码接口
func (a *apiUser) ChangePassword(r *ghttp.Request){
	var(
		data *model.ApiUserChangePasswordReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.User.ChangePassword(r.Context(), data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "密码修改", "修改成功")
		response.JsonExit(r, 200, "ok")
	}
}

// SetUserInfo 用户修改资料接口
func (a *apiUser) SetUserInfo(r *ghttp.Request){
	var(
		data *model.ApiUserSetInfoReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.User.SetUserInfo(r.Context(), data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "资料修改", fmt.Sprintf("成功修改 [%s]", data.NickName))
		response.JsonExit(r, 200, "ok")
	}
}

// Menu 菜单接口
func (a *apiUser) Menu(r *ghttp.Request) {
	r.Response.WriteJson(model.ModuleInit())
}

// LoginOut 用户注销接口
func (a *apiUser) LoginOut(r *ghttp.Request) {
	service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "注销用户", "注销成功")
	if err := service.User.SignOut(r.Context()); err != nil {
		response.JsonExit(r, 1, err.Error())
	}
	response.JsonExit(r, 200, "ok")
}

// SearchUser 用户管理模糊查询分页接口
func (a *apiUser) SearchUser(r *ghttp.Request){
	r.Response.WriteJson(service.User.SearchUser(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SearchUserLockIp ip锁定详情分页接口
func (a *apiUser) SearchUserLockIp(r *ghttp.Request){
	r.Response.WriteJson(service.User.SearchUserLockIp(r.GetInt("page"), r.GetInt("limit")))
}

// UserLockIpRest 解锁ip接口
func (a *apiUser) UserLockIpRest(r *ghttp.Request){
	var (
		data *model.ApiUserLockIpReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.UserLockIpRest(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "解锁IP", fmt.Sprintf("解锁[%s]", data.Ip))
		response.JsonExit(r, 200, "ok")
	}
}

// SearchUserLoginLogs 登录日志管理模糊查询分页接口
func (a *apiUser) SearchUserLoginLogs(r *ghttp.Request){
	r.Response.WriteJson(service.User.SearchUserLoginLogs(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SearchUserOperation 用户操作日志模糊查询分页接口
func (a *apiUser) SearchUserOperation(r *ghttp.Request){
	r.Response.WriteJson(service.User.SearchUserOperation(r.GetInt("page"), r.GetInt("limit"), r.Get("searchParams")))
}

// SendMailConnect smtp连接
func (a *apiUser) SendMailConnect(r *ghttp.Request){
	var(
		data *model.ApiUserSendMailReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.User.SendMailConnect(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "SMTP配置", fmt.Sprintf("SMTP连接成功:[%s]", data.Sender))
		response.JsonExit(r, 200, "ok")
	}
}

// SendMail 发送邮件
func (a *apiUser) SendMail(r *ghttp.Request){
	var(
		data *model.ApiUserSendMaiTitleReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.User.SendMail(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "发送测试邮件", fmt.Sprintf("发送测试邮件成功:[%s]", data.Title))
		response.JsonExit(r, 200, "ok")
	}
}

// GetSmtpInfo 判断smtp是否配置
func (a *apiUser) GetSmtpInfo(r *ghttp.Request){
	if !service.User.GetSmtpInfo(){
		response.JsonExit(r, 202, "未配置smtp")
	}else{
		response.JsonExit(r, 200, "ok")
	}
}

// FtQQSend Server酱发送消息
func (a *apiUser) FtQQSend(r *ghttp.Request){
	var (
		data *model.ApiUserFtqqReq
	)
	if err := r.Parse(&data); err != nil{
		response.JsonExit(r, 201, err.Error())
	}
	if err:= service.User.FtqqSend(data); err != nil{
		response.JsonExit(r, 202, err.Error())
	}else{
		service.User.UserAddOperation(r.Context(), r.GetRemoteIp(), "Server酱发送消息", fmt.Sprintf("发送成功:[%s]", data.Title))
		response.JsonExit(r, 200, "ok")
	}

}

// GetFtQQInfo 判断server酱是否配置
func (a *apiUser) GetFtQQInfo(r *ghttp.Request){
	if !service.User.GetFtqqInfo(){
		response.JsonExit(r, 202, "未配置Server酱")
	}else{
		response.JsonExit(r, 200, "ok")
	}
}