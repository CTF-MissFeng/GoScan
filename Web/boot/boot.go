package boot

import (
	"Web/library/nsq/portscan"
	"time"

	"Web/app/dao"
	"Web/app/model"
	"Web/library/logger"
	Gnsq "Web/library/nsq"
	"Web/library/nsq/producer"
	"Web/library/nsq/suddomain"

	"github.com/gogf/gf/frame/g"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

func init() {
	s := g.Server()

	// web服务器配置
	err := s.SetConfigWithMap(g.Map{
		"address": g.Cfg().Get("server.Address"), // web服务器监听地址
		"serverAgent": "GoScan", // web服务器server信息

		"serverRoot": "public", // 静态文件服务的目录根路径

		"SessionMaxAge": 300 * time.Minute, // session最大超时时间
		"SessionIdName": "GoScan", // session会话ID名称
		"SessionCookieOutput": true, // 指定是否将会话ID自动输出到cookie
	})
	if err != nil {
		logger.WebLog.Fatalf("web服务器配置有误，程序运行失败:%s", err.Error())
	}

	// 静态文件路由设置
	s.SetRewriteMap(g.MapStrStr{
		"/" : "./html/users/login.html",
		"/home": "./html/users/index.html",
		"/user/manager": "./html/users/manager.html",
		"/user/userip": "./html/users/userip.html",
		"/user/loginlog": "./html/users/login_log.html",
		"/user/operation": "./html/users/operation.html",
		"/user/smtp": "./html/users/smtp.html",
		"/user/ftqq": "./html/users/ftqq.html",
		"/user/manager/add": "./html/users/add.html",
		"/user/setting": "./html/users/setting.html",
		"/user/password": "./html/users/password.html",

		"/util/avcheck": "./html/util/avcheck.html",
		"/util/subdomain/manager":"./html/util/SubDomainManager.html",
		"/util/subdomain/manager/add": "./html/util/SubDomainAdd.html",
		"/util/subdomain/manager/show": "./html/util/SubDomainDetails.html",
		"/util/portscan/manager": "./html/util/PortScanManager.html",
		"/util/portscan/manager/add": "./html/util/PortScanAdd.html",
		"/util/portscan/manager/show": "./html/util/PortScanDetails.html",

		"/util/banalyze": "./html/util/BanalyzeManager.html",
		"/util/banalyze/add": "./html/util/BanalyzeAdd.html",
		"/util/banalyze/show": "./html/util/BanalyzeDetails.html",
		"/util/banalyze/scan": "./html/util/BanalyzeScan.html",


		"/scan/manager": "./html/scan/Manager.html",
		"/scan/manager/add": "./html/scan/ManagerAdd.html",
		"/scan/manager/task": "./html/scan/ManagerTask.html",
		"/scan/engine": "./html/scan/Engine.html",
		"/scan/subdomain": "./html/scan/SubDomain.html",
		"/scan/portscan": "./html/scan/Ports.html",
	})
	// 创建测试账户
	createAdmin()

	// 连接nsq消息队列
	producer.NsqInitProducer()
	// 子域名扫描消费者
	suddomain.InitConsumer(Gnsq.RSubDomainTopic, Gnsq.RSubDomainChanl)
	// 端口扫描消费者
	portscan.InitConsumer(Gnsq.RPortScanTopic,Gnsq.RPortScanChanl)
}

// 创建默认admin账户
func createAdmin(){
	if i, err := dao.Users.FindCount("username=?", "admin"); err != nil{
		logger.WebLog.Warningf("[创建默认账户] 查询数据库错误:%s", err.Error())
		return
	}else if i != 0{
		return
	}else{
		passwd,err := bcrypt.GenerateFromPassword([]byte("admin888@A"), bcrypt.DefaultCost)
		if err != nil {
			logger.WebLog.Warningf("[创建默认账户] 加密密码错误:%s", err.Error())
			return
		}else{
			users := model.ApiUserRegisterReq{}
			users.Username = "admin"
			users.Password = string(passwd)
			users.NickName = "管理员"
			users.Email = "admin@qq.com"
			users.Phone = "13888888888"
			users.Remark = "管理员账户"
			if _, err := dao.Users.Insert(users); err != nil {
				logger.WebLog.Warningf("[创建默认账户] 数据库错误:%s", err.Error())
				return
			}
		}
	}
}