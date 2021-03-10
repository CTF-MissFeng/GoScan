package conf

import (
	"io/ioutil"
	"log"

	"github.com/gogf/gf/os/gfile"
)

// 初始化配置文件
func init() {
	data := `
[server]
    Address = "127.0.0.1:9999" # web服务地址，若需要外网访问请填写本机网卡IP地址，防火墙开放此端口
    Password = "admin888" # 用于Client同步配置所需密码，运行后请勿修改此值，否则Client同步配置信息失败

[database]
       host = "127.0.0.1" # postgresql数据库地址
       port = "5432" # postgresql数据库端口
       user = "postgres" # postgresql用户名
       pass = "password" # # postgresql密码
       name = "goscan" # postgresql数据库名(需要自己创建)
       type = "pgsql" # 数据库类型,请勿更改此值
       charset = "utf8" # 数据库编码
       maxOpen = "100" # 连接池最大打开的连接数
       createdAt = "create_at" # 自动创建时间字段名称(请勿更改)
       debug  = false # 是否打印sql执行语句

[nsq]
       HttpHost = "127.0.0.1:4151" # 消息队列HTTP服务地址，对外开放，填写本机网卡地址，防火墙开放此端口
       TcpHost = "127.0.0.1:4150" # 消息队列TCP服务地址，对外开放，填写本机网卡地址，防火墙开放此端口
`
	if !gfile.IsFile("./config.toml"){
		if err := ioutil.WriteFile("config.toml", []byte(data), 0644); err != nil{
			log.Fatalf("配置文件写出失败:%s", err.Error())
		}
		log.Fatal("检测到没有配置文件，config.toml配置文件已生成，请修改配置文件并重新运行")
	}
}