package gospider

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gogf/gf/container/gset"

	cregex "github.com/mingrammer/commonregex"
)

var DefaultHTTPTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout: 10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:    100,
	MaxConnsPerHost: 1000,
	IdleConnTimeout: 30 * time.Second,
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Renegotiation: tls.RenegotiateOnceAsClient},
}

// Requireds 爬虫所需信息
type Requireds struct{
	SiteUrl *url.URL // url
	TimeOuT int64 // 超时
	MaxDepth int // 爬虫深度
	Concurrent int // 并发数
	Delay int // 延迟
}

// Crawler 爬虫保存信息struct
type Crawler struct {
	C *colly.Collector
	LinkFinderCollector *colly.Collector
	SubSet *gset.StrSet // 子域名
	JsSet *gset.StrSet // js文件
	UrlSet *gset.StrSet // url
	FormSet *gset.StrSet // 表单
	Site   *url.URL // URL
	Domain string // 主域名
	KeySet  *gset.StrSet // 敏感信息
}

// NewCrawler 新建爬虫实例
func (r *Requireds)NewCrawler()(*Crawler,error){
	domain := GetDomain(r.SiteUrl)
	if domain == "" {
		return nil, errors.New("获取爬虫Domain失败")
	}
	client := &http.Client{}
	client.Timeout = time.Duration(r.TimeOuT) * time.Second
	client.Transport = DefaultHTTPTransport

	c := colly.NewCollector( // 创建爬虫实例
		colly.MaxDepth(r.MaxDepth), // 设置爬虫深度
		colly.IgnoreRobotsTxt(), // 忽略robots.txt
		colly.MaxBodySize(32768), // 设置读取的响应最大范围 5M
	)
	c.SetClient(client)
	extensions.RandomUserAgent(c) // 随机UA头
	extensions.Referer(c)

	sRegex := regexp.MustCompile(domain)
	c.URLFilters = append(c.URLFilters, sRegex) // 只允许访问该domain下的链接
	// 设置爬虫规则
	err := c.Limit(&colly.LimitRule{
		DomainGlob:  domain,
		Parallelism: r.Concurrent,
		Delay:       time.Duration(r.Delay) * time.Millisecond,
	})
	if err != nil {
		return nil, errors.New("设置爬虫规则失败")
	}
	// 设置爬虫禁用规则
	disallowedRegex := `(?i)\.(png|apng|bmp|gif|ico|cur|jpg|jpeg|jfif|pjp|pjpeg|svg|tif|tiff|webp|xbm|3gp|aac|flac|mpg|mpeg|mp3|mp4|m4a|m4v|m4p|oga|ogg|ogv|mov|wav|webm|eot|woff|woff2|ttf|otf|css)(?:\?|#|$)`
	c.DisallowedURLFilters = append(c.DisallowedURLFilters, regexp.MustCompile(disallowedRegex))

	linkFinderCollector := c.Clone() // 克隆爬虫实例，共享资源
	return &Crawler{
		C:                   c,
		LinkFinderCollector: linkFinderCollector,
		Site:                r.SiteUrl,
		Domain:              domain,
		UrlSet:              gset.NewStrSet(true),
		SubSet:              gset.NewStrSet(true),
		JsSet:               gset.NewStrSet(true),
		FormSet:             gset.NewStrSet(true),
		KeySet: 			 gset.NewStrSet(true),
	}, nil
}

// Start 启动爬虫
func (crawler *Crawler)Start(linkfinder bool) {
	if linkfinder {
		crawler.setupLinkFinder()
	}

	// Handle url
	crawler.C.OnHTML("[href]", func(e *colly.HTMLElement) {
		urlString := e.Request.AbsoluteURL(e.Attr("href"))
		urlString = FixUrl(crawler.Site, urlString,crawler.Domain)
		if urlString == "" {
			return
		}
		fileExt := GetExtType(urlString)
		if fileExt == ".js" || fileExt == ".xml" || fileExt == ".json" {
			if !crawler.JsSet.ContainsI(urlString){
				crawler.JsSet.Add(urlString)
			}
		}else{
			if fileExt != ".css" && fileExt != ".ico"{
				if !crawler.UrlSet.ContainsI(urlString){
					crawler.UrlSet.Add(urlString)
					_ = e.Request.Visit(urlString)
				}
			}
		}
	})

	// Handle form
	crawler.C.OnHTML("form[action]", func(e *colly.HTMLElement) {
		formUrl := e.Request.URL.String()
		formUrl = FixUrl(crawler.Site, formUrl,crawler.Domain)
		if formUrl == "" {
			return
		}
		crawler.FormSet.Add(formUrl)
	})

	// Find Upload Form
	crawler.C.OnHTML(`input[type="file"]`, func(e *colly.HTMLElement) {
		formUrl := e.Request.URL.String()
		formUrl = FixUrl(crawler.Site, formUrl,crawler.Domain)
		if formUrl == "" {
			return
		}
		crawler.FormSet.Add(formUrl)
	})

	// Handle js files
	crawler.C.OnHTML("[src]", func(e *colly.HTMLElement) {
		jsFileUrl := e.Request.AbsoluteURL(e.Attr("src"))
		jsFileUrl = FixUrl(crawler.Site, jsFileUrl,crawler.Domain)
		if jsFileUrl == "" {
			return
		}
		fileExt := GetExtType(jsFileUrl)
		if fileExt == ".js" || fileExt == ".xml" || fileExt == ".json" {
			crawler.JsSet.Add(jsFileUrl)
			if strings.Contains(jsFileUrl, ".min.js") { // 框架不进行查找
				return
			}
			_ = crawler.LinkFinderCollector.Visit(jsFileUrl)
		}
	})

	// Handle respone
	crawler.C.OnResponse(func(response *colly.Response) {
		respStr := DecodeChars(string(response.Body))
		crawler.findSubdomains(respStr)
		crawler.findExp(respStr)
	})

	// Handle Error
	crawler.C.OnError(func(response *colly.Response, err error) {
		if response.StatusCode == 404 || response.StatusCode == 429 || response.StatusCode < 100 || response.StatusCode >= 500 {
			return
		}
		u := response.Request.URL.String()
		crawler.UrlSet.Add(u)
	})

	// 启动爬虫
	crawler.C.Visit(crawler.Site.String())
}

// setupLinkFinder 设置链接查找器
func (crawler *Crawler) setupLinkFinder() {
	crawler.LinkFinderCollector.OnResponse(func(response *colly.Response) {
		if response.StatusCode != 200 {
			return
		}
		respStr := string(response.Body)
		crawler.findSubdomains(respStr)
		crawler.findExp(respStr)
		paths, err := LinkFinder(respStr)
		if err != nil {
			return
		}

		var inScope bool
		if InScope(response.Request.URL, crawler.C.URLFilters) {
			inScope = true
		}
		for _, relPath := range paths {
			rebuildURL := FixUrl(crawler.Site, relPath,crawler.Domain)
			if rebuildURL == "" {
				continue
			}
			if rebuildURL != "" {
				_ = crawler.C.Visit(rebuildURL)
			}
			if inScope {
				urlWithJSHostIn := FixUrl(crawler.Site, relPath,crawler.Domain)
				if urlWithJSHostIn != "" {
					_ = crawler.C.Visit(urlWithJSHostIn)
				}
			}
		}
	})
}

// findSubdomains 查找子域名
func (crawler *Crawler) findSubdomains(resp string) {
	subs := GetSubdomains(resp, crawler.Domain)
	for _, sub := range subs {
		crawler.SubSet.Add(sub)
	}
}

// findExp
func (crawler *Crawler) findExp(resp string){
	emails := cregex.Emails(resp)
	if len(emails) != 0{
		for _,v := range emails {
			crawler.KeySet.Add(v)
		}
	}
	ips := cregex.IPv4s(resp)
	if len(ips) != 0{
		for _,v := range ips {
			crawler.KeySet.Add(v)
		}
	}

}