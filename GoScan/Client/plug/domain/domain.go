package domain

import (
	"sync"

	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/dnsprobe"
	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/rapid7"
	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/subfinder/runner"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/gogf/gf/container/gset"
)

// 获取子域名
func GetSubdomain(domain string)([]*dnsprobe.ResSubdomain, error){
	resultChanl := make(chan []string,2)

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rapid7Client,err := rapid7.NewCrobatClient()
		if err != nil {
			logger.LogDomain.Warningf("子域名[%s]rapid7查询失败:%s", domain, err.Error())
			return
		}
		lists,err := rapid7Client.GetSubdomains(domain)
		if err == nil {
			resultChanl <- lists
		}
	}()

	go func() {
		defer wg.Done()
		subfinderClient := runner.Runner{}
		lists := subfinderClient.Run(domain)
		resultChanl <- lists
	}()

	wg.Wait()
	close(resultChanl)
	subdomains := gset.NewStrSet()
	for tmp := range resultChanl{
		for _,subdoamin := range tmp{
			subdomains.Add(subdoamin)
		}
	}
	if subdomains.Size() == 0{ // 未发现子域名
		logger.LogDomain.Infof("子域名[%s]扫描完毕,未发现子域名", domain)
		return nil, nil
	}
	logger.LogDomain.Infof("子域名扫描完毕,共计[%d]个", subdomains.Size())
	results,err := dnsprobe.Run(subdomains.Slice())
	if err != nil{
		logger.LogDomain.Warningf("子域名解析错误:%s", err.Error())
		return nil, err
	}
	if results == nil{
		logger.LogDomain.Infof("子域名[%s]扫描完毕,DNS解析后无数据", domain)
		return nil, nil
	}
	logger.LogDomain.Debugf("子域名解析完成,共计[%d]个", len(results))
	return results, nil
}
