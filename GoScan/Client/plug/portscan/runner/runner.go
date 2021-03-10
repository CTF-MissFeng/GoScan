package runner

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/portscan/probe"
	"github.com/CTF-MissFeng/GoScan/Client/plug/portscan/public"
	"github.com/CTF-MissFeng/GoScan/Client/plug/portscan/scan"
	"github.com/CTF-MissFeng/GoScan/Client/util/conf"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/ns3777k/go-shodan/v4/shodan"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

// 初始化端口扫描
func Init(){
	if !public.IsOSSupported(){
		logger.LogPortScan.Info("[+] 检测到当前系统为非linux系统,使用Connect方式扫描")
	}else{
		if !public.IsRoot(){
			logger.LogPortScan.Warningf("[+] 提示：检测到当前用户非root用户，请使用sudo运行")
		}
		public.SetUlimit() // 设置系统ulimit值
	}
	err := scan.NewScanner() // 实例化scanner
	if err != nil{
		logger.LogPortScan.Fatalf("[-] 初始化端口扫描失败:%s", err.Error())
	}
}

// 开始进行端口扫描
func Run()error{
	portList, err := public.ParsePorts() // 解析端口参数
	if err != nil {
		return err
	}

	// 判断是否存活扫描
	if public.GOptions.Ping{
		err1 := scan.PingHost(public.GOptions.Hosts)
		if err1 != nil {
			logger.LogPortScan.Debugf("[-] %s Ping探测不存活", public.GOptions.Hosts)
			return err1
		}
		logger.LogPortScan.Debugf("[+] %s Ping探测存活", public.GOptions.Hosts)
	}

	limiter := ratelimit.New(public.GOptions.Rate) // 设置发包速率,每秒执行的数量
	wgscan := sizedwaitgroup.New(public.GOptions.Rate) // connect并发限制
	scan.GScan.State = scan.Scan // 设置扫描状态
	Range := int64(len(portList)) // 循环次数
	var currentRetry int // 重试次数标识
	isLinux := public.IsOSSupported()
	if !isLinux{
		logger.LogPortScan.Debugf("[-] %s 非root用户使用connect扫描", public.GOptions.Hosts)
	}
retry:
	for index := int64(0); index < Range; index++ {
		ip := public.GOptions.Hosts
		port := portList[index]
		if isLinux{
			limiter.Take() // 开始限速
			scan.GScan.EnqueueTCP(ip, port, scan.SYN)
		}else{
			wgscan.Add()
			go handleHostPort(ip, port, &wgscan)
		}
	}

	currentRetry++
	if currentRetry <= public.GOptions.Retries { // 重试次数
		goto retry
	}
	scan.GScan.State = scan.Init // 设置扫描标识为准备状态

	if public.GOptions.Verify { // 是否需要二次验证端口结果
		connectVerification()
	}

	return nil
}

// 二次验证端口结果
func connectVerification() {
	var swg sync.WaitGroup
	host := public.GOptions.Hosts
	ports := scan.GScan.ScanResults.Ports
	scan.GScan.ScanResults.DeletePorts()

	for port := range ports {
		swg.Add(1)
		tmpPort := port
		go func() {
			defer swg.Done()
			flag,resultPort := scan.ConnectVerify(host, tmpPort, public.GOptions.Timeout)
			if flag{
				scan.GScan.ScanResults.AddPort(resultPort)
			}
		}()
	}
	swg.Wait()
}

// 输出端口扫描结果
func Output()(int, []*probe.Task){
	defer scan.GScan.ScanResults.DeletePorts()

	if len(scan.GScan.ScanResults.Ports) == 0{
		logger.LogPortScan.Infof("[-] %s 未发现存活端口,进行ShoDan搜索端口", public.GOptions.Hosts)
		ports,err := ShoDanPorts(public.GOptions.Hosts)
		if err != nil {
			logger.LogPortScan.Warningf("[-] ShoDan搜索失败:%s", err.Error())
			return 0, nil
		}
		scan.GScan.ScanResults.DeletePorts()
		for _,tmp := range ports{
			scan.GScan.ScanResults.AddPort(tmp)
		}
		connectVerification()
		if len(scan.GScan.ScanResults.Ports) == 0{
			return 0, nil
		}
		logger.LogPortScan.Debugf("[+] ShoDan找到%s个端口", len(scan.GScan.ScanResults.Ports))
	}

	if len(scan.GScan.ScanResults.Ports) > public.GOptions.WafNum{ // 判断端口数量是否为waf
		logger.LogPortScan.Infof("[-] %s 探测到%d个存活端口 判定为WAF,进行ShoDan搜索端口", public.GOptions.Hosts, len(scan.GScan.ScanResults.Ports))
		ports,err := ShoDanPorts(public.GOptions.Hosts)
		if err != nil {
			logger.LogPortScan.Warningf("[-] ShoDan搜索失败:%s", err.Error())
			return 0, nil
		}
		scan.GScan.ScanResults.DeletePorts()
		for _,tmp := range ports{
			scan.GScan.ScanResults.AddPort(tmp)
		}
		connectVerification()
		if len(scan.GScan.ScanResults.Ports) == 0{
			return 0, nil
		}
		logger.LogPortScan.Debugf("[+] ShoDan找到%s个端口", len(scan.GScan.ScanResults.Ports))
	}

	logger.LogPortScan.Infof("[+] %s 探测到%d个存活端口 %v", public.GOptions.Hosts, len(scan.GScan.ScanResults.Ports), scan.GScan.ScanResults.Ports)
	if public.GOptions.Detection != "null"{ // 是否进行优先扫描
		return len(scan.GScan.ScanResults.Ports), nil
	}

	result := nmapIdentify()
	for _, res := range result{
		logger.LogPortScan.Debugf("[+] %s  [%s] %s %s %s %d %s", res.Addr, res.ServiceNmae, res.VendorProduct,
			res.Version, res.Url, res.StatusCode, res.Title)
	}
	return len(scan.GScan.ScanResults.Ports), result
}

// 单IP多端口指纹识别
func nmapIdentify()[]*probe.Task{
	result := make([]*probe.Task, 0) // 保存端口指纹识别结果

	wg := sync.WaitGroup{}
	resultChan := make(chan *probe.Task, len(scan.GScan.ScanResults.Ports)) // 保存并发的运行结果

	for port := range scan.GScan.ScanResults.Ports{
		wg.Add(1)
		go func(v string){
			defer wg.Done()
			probe.Gnmaps.ScanWithProbe(public.GOptions.Hosts, v, public.GOptions.NmapTimeout, resultChan)
		}(strconv.Itoa(port))
	}

	wg.Wait() // 等待协程运行完毕
	close(resultChan)
	for task := range resultChan{
		result = append(result, task)
	}
	return result
}

// Connect 方式扫描
func handleHostPort(host string, port int, wg *sizedwaitgroup.SizedWaitGroup) {
	defer wg.Done()

	open, err := scan.ConnectPort(host, port, time.Duration(public.GOptions.Timeout)*time.Millisecond)
	if open && err == nil {
		scan.GScan.ScanResults.AddPort(port)
	}
}

// ShoDan搜索指定主机端口
func ShoDanPorts(host string)([]int, error){
	if conf.Gconf.ApiKey.Shodan == ""{
		return nil, errors.New("未配置ShoDan秘钥")
	}
	Client := shodan.NewClient(nil,conf.Gconf.ApiKey.Shodan)
	results,err := Client.GetServicesForHost(context.Background(), host,nil)
	if err != nil{
		return nil, err
	}
	if len(results.Ports) == 0{
		return nil, errors.New("无端口数据")
	}
	return results.Ports, nil
}