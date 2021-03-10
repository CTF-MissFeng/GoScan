package router

import (
	"github.com/CTF-MissFeng/GoScan/Web/app/api"
	"github.com/CTF-MissFeng/GoScan/Web/app/service"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
)

func init() {
	s := g.Server()
	s.Group("/api", func(group *ghttp.RouterGroup) {
		group.Middleware(service.Middleware.Ctx)
		group.POST("/login", api.Users.Login)
		group.GET("/client/info",api.Scan.GetApiKeyEngine)

		group.Group("/user", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.GET("/index", api.Users.UserInfo)
			group.POST("/index", api.Users.SetUserInfo)
			group.PUT("/index", api.Users.ChangePassword)
			group.DELETE("/index", api.Users.UserDel)
			group.POST("/add", api.Users.Register)
			group.GET("/menu", api.Users.Menu)
			group.GET("/manager", api.Users.SearchUser)
			group.GET("/lock", api.Users.SearchUserLockIp)
			group.DELETE("/lock", api.Users.UserLockIpRest)
			group.GET("/log", api.Users.SearchUserLoginLogs)
			group.GET("/logs", api.Users.SearchUserOperation)
			group.GET("/smtp", api.Users.GetSmtpInfo)
			group.POST("/smtp", api.Users.SendMailConnect)
			group.PUT("/smtp", api.Users.SendMail)
			group.GET("/out", api.Users.LoginOut)
		})

		group.Group("/util", func(group *ghttp.RouterGroup) {
			group.Middleware(service.Middleware.Auth)
			group.POST("/avcheck", api.Util.AvCheck)

			group.POST("/subdomain/add",api.Util.SubDomainAdd)
			group.GET("/subdomain/show", api.Util.SearchSubDomainShow)
			group.GET("/subdomain", api.Util.SearchSubDomainManager)
			group.GET("/subdomain/export/:name", api.Util.ExportSubDomainXlsx)
			group.DELETE("/subdomain", api.Util.SubDomainDel)
			group.PUT("/subdomain", api.Util.SubDomainEmpty)
			group.GET("/subdomain/nsq", api.Util.SubDomainNSqStats)

			group.POST("/portscan/add", api.Util.PortScanAdd)
			group.GET("/portscan", api.Util.SearchPortManager)
			group.GET("/portscan/nsq", api.Util.PortScanNSqStats)
			group.DELETE("/portscan", api.Util.PortScanDel)
			group.PUT("/portscan", api.Util.PortScanEmpty)
			group.GET("/portscan/show", api.Util.SearchPortScanShow)
			group.GET("/portscan/export/:name", api.Util.ExportPortScanXlsx)
			group.POST("/portscan/echarts",api.Util.PortScanEchartsInfo)

			group.GET("/banalyze", api.Util.SearchBanalyzeManager)
			group.PUT("/banalyze", api.Util.BanalyzeEmpty)
			group.POST("/banalyze/add", api.Util.BanalyzeAdd)
			group.DELETE("/banalyze", api.Util.BanalyzeDelete)
			group.POST("/banalyze/show", api.Util.BanalyzeShow)
			group.PUT("/banalyze/show", api.Util.BanalyzeUpdate)
			group.GET("/banalyze/export", api.Util.BanalyzeExport)
			group.POST("/banalyze/upload", api.Util.BanalyzeUpload)
			group.GET("/banalyze/scan", api.Util.BanalyzeScan)

		})

		group.Group("/scan", func(group *ghttp.RouterGroup){
			group.Middleware(service.Middleware.Auth)
			group.PUT("/manager", api.Scan.ManagerAdd)
			group.GET("/manager", api.Scan.SearchManager)
			group.DELETE("/manager", api.Scan.ManagerDelete)
			group.POST("/manager", api.Scan.DomainAdd)
			group.GET("/domain",api.Scan.SearchDomain)
			group.POST("/engine/nsq", api.Scan.APIKeyEngineNsqAdd)
			group.POST("/engine/portscan", api.Scan.ApiKeyEnginePortScanAdd)
			group.POST("/engine/domain", api.Scan.ApiKeyEngineDomainAdd)
			group.POST("/engine/apikey",api.Scan.ApiKeyEngineKeyAdd)
			group.POST("/engine/webinfo",api.Scan.ApiKeyEngineWebInfoAdd)
			group.GET("/engine/info",api.Scan.GetApiKeyEngineInfo)
			group.GET("/engine/portnsq",api.Scan.PortNSqStats)
			group.GET("/engine/domainnsq",api.Scan.DomainNSqStats)
			group.GET("/engine/webinfonsq",api.Scan.WebInfoNSqStats)
			group.DELETE("/engine/emptydomain",api.Scan.EmptyDomain)
			group.DELETE("/engine/emptyport",api.Scan.EmptyPort)
			group.DELETE("/engine/emptywebinfo",api.Scan.EmptyWebInfo)
			group.GET("/group/cusname", api.Scan.GetApiCusName)
			group.GET("/subdomain",api.Scan.SearchSubDomain)
			group.GET("/ports",api.Scan.SearchPortScan)
			group.GET("/webinfo",api.Scan.SearchWebInfo)
			group.POST("/webinfo/tree",api.Scan.WebInfoTree)
			group.DELETE("/webinfo",api.Scan.WebInfoDel)
		})
	})
}