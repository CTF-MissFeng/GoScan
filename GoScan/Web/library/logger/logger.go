package logger

import (
	"github.com/gogf/gf/os/glog"
)

var WebLog *glog.Logger

// init 初始化日志
func InitLogs()  {
	logs := glog.New()
	logs.SetPath("logs")
	logs.SetLevelStr("all")
	WebLog = logs
}