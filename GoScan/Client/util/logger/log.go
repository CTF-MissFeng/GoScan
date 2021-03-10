package logger

import (
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/glog"
)

var Log *glog.Logger
var LogPortScan *glog.Logger
var LogDomain *glog.Logger
var LogWebInfo *glog.Logger

func init() {
	LogPortScan = glog.New()
	LogPortScan.SetConfigWithMap(g.Map{
		"path":     "logs",
		"level":    g.Cfg().GetString("PortScan.Level"),
		"file": "portscan-{Y-m-d}.log",
		"prefix": "端口扫描",
	})

	Log = glog.New()
	Log.SetConfigWithMap(g.Map{
		"path":     "logs",
		"level":    "all",
		"file": "client-{Y-m-d}.log",
		"prefix": "GoScan",
	})

	LogDomain = glog.New()
	LogDomain.SetConfigWithMap(g.Map{
		"path":     "logs",
		"level":    g.Cfg().GetString("Domain.Level"),
		"file": "domain-{Y-m-d}.log",
		"prefix": "子域名扫描",
	})

	LogWebInfo = glog.New()
	LogWebInfo.SetConfigWithMap(g.Map{
		"path":     "logs",
		"level":    g.Cfg().GetString("WebInfo.Level"),
		"file": "web-{Y-m-d}.log",
		"prefix": "web探测",
	})
}