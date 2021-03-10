package service

import (
	"context"

	"github.com/CTF-MissFeng/GoScan/Web/library/response"

	"github.com/gogf/gf/net/ghttp"
)

var Text = new(serviceUserText)

type serviceUserText struct{}

// IsUserText 判断是否为测试用户
func (s *serviceUserText)IsUserText(r *ghttp.Request,ctx context.Context){
	user := Session.GetUser(ctx)
	if user.Username == "test"{
		response.JsonExit(r,201, "test测试用户无权限使用该功能")
	}
}