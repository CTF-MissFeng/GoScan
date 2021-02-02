package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "Client/util/conf"
	_ "Client/util/logger"
	Gnsq "Client/util/nsq"
	"Client/util/nsq/Production"
	"Client/util/nsq/portscan"
	"Client/util/nsq/subdomain"

	"github.com/gogf/gf/frame/g"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
)

func main() {
	Production.NsqInitProducer() // 初始化Nsq生产者

	if g.Cfg().GetBool("Domain.Enabled"){ // 子域名扫描
		log.Println("[+] 子域名模块开启")
		subdomain.InitConsumer(Gnsq.SubDomainTopic, Gnsq.SubDomainChanl)
	}

	if g.Cfg().GetBool("PortScan.Enabled"){ // 端口扫描
		log.Println("[+] 端口扫描模块开启")
		portscan.Init()
	}

	c := make(chan os.Signal)        // 定义一个信号的通道
	signal.Notify(c, syscall.SIGINT) // 转发键盘中断信号到c
	<-c                              // 阻塞

	defer Production.NsqProducer.Stop() // 停止生产者
}
