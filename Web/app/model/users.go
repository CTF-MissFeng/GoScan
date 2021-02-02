package model

import (
	"Web/app/model/internal"
)

type Users internal.Users

// 登录请求参数
type ApiUserLoginReq struct {
	Username string `v:"required|length:4,16#账号不能为空|账号长度应当在:min到:max之间"`
	Password string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
}

// 添加用户请求参数
type ApiUserRegisterReq struct{
	Username string `v:"required|length:4,16#账号不能为空|账号长度应当在:min到:max之间"`
	Password string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
	NickName string `v:"required#昵称不能为空"`
	Phone string `v:"required|phone#手机号不能为空|手机号格式不正确"`
	Email string `v:"required|email#邮箱不能为空|邮箱格式不正确"`
	Remark string `v:"required#个性签名不能为空"`
}

// 删除用户所需信息
type ApiUserDelReq struct{
	Username string `v:"required|length:4,16#账号不能为空|账号长度应当在:min到:max之间"`
}

// 修改密码所需信息
type ApiUserChangePasswordReq struct {
	Password string `v:"required|length:6,20|password3|different:Password1#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号|新密码不能和旧密码一致"`
	Password1 string `v:"required|length:6,20|password3#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号"`
	Password2 string `v:"required|length:6,20|password3|same:Password2#密码不能为空|密码长度应当在:min到:max之间|密码应包含大小写数字及特殊符号|两次密码输入不相等"`
}

// 用户修改资料所需信息
type ApiUserSetInfoReq struct {
	NickName string `v:"required#昵称不能为空"`
	Phone string `v:"required|phone#手机号不能为空|手机号格式不正确"`
	Email string `v:"required|email#邮箱不能为空|邮箱格式不正确"`
	Remark string `v:"required#个性签名不能为空"`
}

// 用户管理 模糊分页查询返回数据所需信息
type ResAPiUserManager struct{
	Code int `json:"code"`
	Msg string `json:"msg"`
	Count int64 `json:"count"`
	Data [] *Users `json:"data"`
}

// IP锁定管理 模糊分页查询返回数据所需信息
type ResAPiUserLockIp struct{
	Code int `json:"code"`
	Msg string `json:"msg"`
	Count int64 `json:"count"`
	Data [] *UserIp `json:"data"`
}

// 解锁IP所需信息
type ApiUserLockIpReq struct{
	Ip string `v:"required|ip#需要解锁的IP不能为空|IP格式不正确"`
}

// 用户登录日志管理 模糊分页查询返回数据所需信息
type ResAPiUserLoginLogs struct{
	Code int `json:"code"`
	Msg string `json:"msg"`
	Count int64 `json:"count"`
	Data [] *UserLog `json:"data"`
}

// 用户操作日志管理 模糊分页查询返回数据所需信息
type ResAPiUserOperation struct{
	Code int `json:"code"`
	Msg string `json:"msg"`
	Count int64 `json:"count"`
	Data [] *UserOperation `json:"data"`
}

// SMTP连接发送邮件所需信息
type ApiUserSendMailReq struct{
	Host string `v:"required#Host不能为空"`
	Port string `v:"required|integer#端口不能为空|端口必须为整数"`
	Username string `v:"required#用户名不能为空"`
	Password string `v:"required#密码不能为空"`
	Sender string `v:"required|email#发件人不能为空|发件人格式错误"`
}

// 发送邮件所需信息
type ApiUserSendMaiTitleReq struct{
	Address string `v:"required|email#收件人不能为空|收件人格式错误"`
	Title string `v:"required#邮件标题不能为空"`
	Content string `v:"required#邮件内容不能为空"`
}

// Service酱所需信息
type ApiUserFtqqReq struct{
	Sckey string `v:"required#SCKEY值不能为空"`
	Title string `v:"required#标题不能为空"`
	Content string `v:"required#内容不能为空"`
}