package service

import (
	"context"

	"github.com/CTF-MissFeng/GoScan/Web/app/model"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
)

const (
	sessionKeyUser = "GoScan"
)

// 中间件管理服务
var Middleware = new(serviceMiddleware)

// Session管理服务
var Session = new(serviceSession)

// 上下文管理服务
var Context = new(serviceContext)

type serviceMiddleware struct{}

type serviceSession struct{}

type serviceContext struct{}

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

// 设置用户Session.
func (s *serviceSession) SetUser(ctx context.Context, user *model.Users) error {
	return Context.Get(ctx).Session.Set(sessionKeyUser, user)
}

// 获取当前登录的用户信息对象，如果用户未登录返回nil。
func (s *serviceSession) GetUser(ctx context.Context) *model.Users {
	customCtx := Context.Get(ctx)
	if customCtx != nil {
		if v := customCtx.Session.GetVar(sessionKeyUser); !v.IsNil() {
			var user *model.Users
			_ = v.Struct(&user)
			return user
		}
	}
	return nil
}

// 删除用户Session。
func (s *serviceSession) RemoveUser(ctx context.Context) error {
	customCtx := Context.Get(ctx)
	if customCtx != nil {
		return customCtx.Session.Remove(sessionKeyUser)
	}
	return nil
}

// 初始化上下文对象指针到上下文对象中，以便后续的请求流程中可以修改。
func (s *serviceContext) Init(r *ghttp.Request, customCtx *model.Context) {
	r.SetCtxVar(model.ContextKey, customCtx)
}

// 获得上下文变量，如果没有设置，那么返回nil
func (s *serviceContext) Get(ctx context.Context) *model.Context {
	value := ctx.Value(model.ContextKey)
	if value == nil {
		return nil
	}
	if localCtx, ok := value.(*model.Context); ok {
		return localCtx
	}
	return nil
}

// 将上下文信息设置到上下文请求中，注意是完整覆盖
func (s *serviceContext) SetUser(ctx context.Context, ctxUser *model.ContextUser) {
	s.Get(ctx).User = ctxUser
}