package service

import (
	"Web/app/model"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
)

// 中间件管理服务
var Middleware = new(serviceMiddleware)

type serviceMiddleware struct{}

// 自定义上下文对象
func (s *serviceMiddleware) Ctx(r *ghttp.Request) {
	// 初始化，务必最开始执行
	customCtx := &model.Context{
		Session: r.Session,
	}
	Context.Init(r, customCtx)
	if user := Session.GetUser(r.Context()); user != nil {
		customCtx.User = &model.ContextUser{
			Id:       user.Id,
			UserName: user.Username,
			Email: user.Email,
		}
	}
	// 执行下一步请求逻辑
	r.Middleware.Next()
}

// 鉴权中间件，只有登录成功之后才能通过
func (s *serviceMiddleware) Auth(r *ghttp.Request) {
	if User.IsSignedIn(r.Context()) {
		r.Middleware.Next()
	} else {
		r.Response.WriteJsonExit(g.Map{"code": 403, "msg":"非法访问", "data":""})
	}
}
