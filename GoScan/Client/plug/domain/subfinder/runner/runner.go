package runner

import (
	"strings"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/subfinder/passive"
	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/subfinder/subscraping"
	"github.com/CTF-MissFeng/GoScan/Client/util/conf"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/gogf/gf/container/gset"
)

type Runner struct {
	passiveAgent   *passive.Agent
}

// 开始执行子域名探测
func (r *Runner) Run(domain string)[]string{
	r.passiveAgent = passive.New(passive.DefaultAllSources)
	logger.LogDomain.Debugf("开始进行被动搜索子域名:%s", domain)
	key := subscraping.Keys{}
	key.Shodan = conf.Gconf.ApiKey.Shodan
	key.Binaryedge = conf.Gconf.ApiKey.Binaryedge
	key.CensysToken = conf.Gconf.ApiKey.CensysToken
	key.CensysSecret = conf.Gconf.ApiKey.CensysSecret
	key.Certspotter = conf.Gconf.ApiKey.Certspotter
	key.GitHub = []string{conf.Gconf.ApiKey.GitHub}
	key.Spyse = conf.Gconf.ApiKey.Spyse
	key.Securitytrails = conf.Gconf.ApiKey.Securitytrails
	key.ThreatBook = conf.Gconf.ApiKey.ThreatBook
	key.URLScan = conf.Gconf.ApiKey.URLScan
	key.Virustotal = conf.Gconf.ApiKey.Virustotal

	passiveResults := r.passiveAgent.EnumerateSubdomains(domain, &key, conf.Gconf.Domain.Timeout, time.Duration(conf.Gconf.Domain.MaxEnumTime)*time.Minute)
	sudomainSet := gset.NewStrSet()
	for result := range passiveResults {
		switch result.Type {
		case subscraping.Subdomain:
			if !strings.HasSuffix(result.Value, "."+domain) {
				continue
			}
			subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
			sudomainSet.Add(subdomain)
		}
	}
	logger.LogDomain.Infof("被动子域名探测结果[%d]个", sudomainSet.Size())
	return sudomainSet.Slice()
}