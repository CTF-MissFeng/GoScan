package logger

import (
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/glog"
)

var WebLog *glog.Logger

func init()  {
	logger := glog.New()
	logger.SetConfigWithMap(g.Map{
		"path":     "log",
		"level":    "all",
	})
	WebLog = logger
}
