package gospider

import (
	"net/url"
	"path"
	"regexp"

	"golang.org/x/net/publicsuffix"
)

// GetDomain 根据URL获取Domain
func GetDomain(site *url.URL) string {
	domain, err := publicsuffix.EffectiveTLDPlusOne(site.Hostname())
	if err != nil {
		return ""
	}
	return domain
}

// InScope 判断URL是否在源内
func InScope(u *url.URL, regexps []*regexp.Regexp) bool {
	for _, r := range regexps {
		if r.MatchString(u.Hostname()) {
			return true
		}
	}
	return false
}

// FixUrl 修复URL
func FixUrl(mainSite *url.URL, nextLoc string, domain string) string {
	nextLocUrl, err := url.Parse(nextLoc)
	if err != nil {
		return ""
	}
	url1 := mainSite.ResolveReference(nextLocUrl).String()
	nextLocUrl1, err := url.Parse(url1)
	if err != nil {
		return ""
	}
	if domain != GetDomain(nextLocUrl1){
		return ""
	}else{
		return nextLocUrl1.String()
	}
}

// GetExtType 获取URL后缀名
func GetExtType(rawUrl string) string {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return ""
	}
	return path.Ext(u.Path)
}