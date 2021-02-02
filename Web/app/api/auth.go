package api

import (
	"Web/app/model"
	"Web/app/service"
	"Web/library/response"
	"github.com/gogf/gf/net/ghttp"
)

// 用户API管理对象
var Auth = new(apiAuth)

type apiAuth struct{}

// Login 用户登录接口
func (a *apiAuth) Login(r *ghttp.Request) {
	var (
		data *model.ApiUserLoginReq
	)
	if err := r.Parse(&data); err != nil {
		response.JsonExit(r, 201, err.Error())
	}
	if err := service.User.Login(r.Context(), data.Username, data.Password, r.GetRemoteIp(), r.GetHeader("User-Agent")); err != nil {
		response.JsonExit(r, 202, err.Error())
	}else {
		response.JsonExit(r, 200, "ok")
	}
}