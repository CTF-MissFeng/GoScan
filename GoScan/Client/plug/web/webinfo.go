package web

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/web/banalyze"
	"github.com/CTF-MissFeng/GoScan/Client/plug/web/gospider"
	"github.com/CTF-MissFeng/GoScan/Client/util/conf"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/axgle/mahonia"
	"github.com/gogf/gf/crypto/gmd5"
	"github.com/gogf/gf/encoding/ghtml"
	"github.com/gogf/gf/os/grpool"
	"github.com/gogf/gf/text/gregex"
	"github.com/gogf/gf/util/gconv"
	"github.com/parnurzeal/gorequest"
	"github.com/saintfish/chardet"
)

// ResultWebInfo web探测返回信息
type ResultWebInfo struct{
	Url string `json:"url"`
	StatusCode int `json:"status_code"`
	Title string `json:"title"`
	ContentLength int `json:"content_length"`
	Banalyze map[string]*banalyze.ResultApp `json:"banalyze"`
	SubDomaina []string `json:"subdomaina"`
	Js []string `json:"js"`
	Urls []string `json:"urls"`
	Forms []string `json:"forms"`
	Keys []string `json:"keys"`
}

// Detection web探测所需信息
type Detection struct{
	SubDomain []string
	ServiceName string
	Port int
}

// GetWebInfo web探测
func (d *Detection)GetWebInfo()[]*ResultWebInfo{
	var GResultWebInfo []*ResultWebInfo
	pool := grpool.New(20)
	wg := sync.WaitGroup{}
	resultChanl := make(chan *HttpInfo, len(d.SubDomain))
	for _,v := range d.SubDomain{
		wg.Add(1)
		tmp := v
		pool.Add(func() {
			getHttp := HttpInfo{SubDomain:tmp, ServiceName:d.ServiceName, Port:d.Port, Timeout:conf.Gconf.WebInfo.WappalyzerTimeout}
			getHttp.SendHttp()
			if getHttp.StatusCode != 0{
				resultChanl <- &getHttp
			}
			defer wg.Done()
		})
	}
	wg.Wait()
	close(resultChanl)
	exclude := make(map[string]struct{})
	for v := range resultChanl{
		key := gconv.String(v.ContentLength)+gconv.String(v.StatusCode)+v.Title
		md5,err := gmd5.EncryptString(key)
		if err != nil {
			logger.LogWebInfo.Warningf("MD5转换失败:%s", err.Error())
			continue
		}
		if _,ok := exclude[md5];!ok{
			exclude[md5]= struct{}{}
			GResultWebInfo = append(GResultWebInfo, &ResultWebInfo{
				Url:v.Url,
				StatusCode:v.StatusCode,
				Title:v.Title,
				ContentLength:v.ContentLength,
			})
			logger.LogWebInfo.Debugf("%s %s", v.Url, v.Title)
		}
	}

	banalyze.LoadApps(conf.Gconf.Banalyze)
	banalyzeChanl := make(chan map[string]map[string]*banalyze.ResultApp, len(GResultWebInfo))
	wg1 := sync.WaitGroup{}
	for _,v := range GResultWebInfo{
		wg1.Add(1)
		go func(tmpurl string){
			res,err := banalyze.Gbanalyze.Analyze(tmpurl, conf.Gconf.WebInfo.WappalyzerTimeout)
			if err == nil {
				banalyzeChanl <- map[string]map[string]*banalyze.ResultApp{tmpurl:res}
			}
			defer wg1.Done()
		}(v.Url)
	}
	wg1.Wait()
	close(banalyzeChanl)
	for key := range banalyzeChanl{
		for k := range key{
			InsertResults(k,  key[k], GResultWebInfo)
		}
	}

	for _,v := range GResultWebInfo{
		if v.StatusCode != 200{
			continue
		}
		spiderURL,err := url.Parse(v.Url)
		if err != nil {
			logger.LogWebInfo.Warningf("爬虫-URL解析错误:%s", err.Error())
			continue
		}
		spider := gospider.Requireds{
			SiteUrl:spiderURL,
			TimeOuT:int64(conf.Gconf.WebInfo.SpiderTimeout),
			MaxDepth:conf.Gconf.WebInfo.MaxDepth,
			Concurrent:conf.Gconf.WebInfo.Concurrent,
			Delay:1,
		}
		crawler,err := spider.NewCrawler()
		if err != nil {
			logger.LogWebInfo.Warningf("爬虫-启动爬虫错误:%s", err.Error())
			continue
		}
		crawler.Start(true)
		v.Js = crawler.JsSet.Slice()
		v.Urls = crawler.UrlSet.Slice()
		v.Forms = crawler.FormSet.Slice()
		v.Keys = crawler.KeySet.Slice()
		v.SubDomaina = crawler.SubSet.Slice()
	}

	for _, v := range GResultWebInfo{
		logger.LogWebInfo.Debugf("爬虫结果：%s js文件:%d URL:%d 子域名:%d 敏感信息:%d", v.Url, len(v.Js), len(v.Urls),len(v.SubDomaina), len(v.Keys))
	}
	return GResultWebInfo
}

type HttpInfo struct{
	SubDomain string
	ServiceName string
	Port int
	Url string
	StatusCode int
	Title string
	ContentLength int
	Timeout int
}

// 发送HTTP数据包
func (h *HttpInfo)SendHttp(){
	if strings.Contains(h.ServiceName, "http") && !strings.Contains(h.ServiceName, "https"){
		h.Url = fmt.Sprintf("https://%s:%d", h.SubDomain, h.Port)
		err := h.SendHttp1()
		if err != nil{
			h.Url = fmt.Sprintf("http://%s:%d", h.SubDomain, h.Port)
			h.SendHttp1()
		}
	}else{
		h.Url = fmt.Sprintf("https://%s:%d", h.SubDomain, h.Port)
		h.SendHttp1()
	}
}

// 发送HTTP数据包
func (h *HttpInfo)SendHttp1()error{
	resp, body, err := gorequest.New().
		Get(h.Url).
		Timeout(time.Duration(int64(h.Timeout))*time.Second).
		TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
		AppendHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		AppendHeader("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/538.41 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
		End()
	if err != nil{
		return err[0]
	}
	h.StatusCode = resp.StatusCode
	h.ContentLength = len(body)
	h.getTitle(body)
	return nil
}

// 获取网页标题
func (h *HttpInfo)getTitle(s string){
	list,err := gregex.MatchString("<title>(.*?)</title>", s)
	if err != nil{
		return
	}
	if len(list) == 0{
		return
	}
	title := list[len(list)-1]
	detector:=chardet.NewTextDetector()
	char,err := detector.DetectBest([]byte(title)) // 检测编码类型
	if err != nil{
		return
	}
	if char.Charset == "UTF-8"{
		h.Title = ghtml.SpecialChars(title)
		return
	}
	h.Title = h.ConvertToString(ghtml.SpecialChars(title),"GBK", "utf-8")
	return
}

// 编码转换成utf-8编码
func (h *HttpInfo)ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}

// InsertResults
func InsertResults(k string, data map[string]*banalyze.ResultApp, GResultWebInfo []*ResultWebInfo){
	for i, v := range GResultWebInfo{
		if k == v.Url{
			GResultWebInfo[i].Banalyze = data
			for _,v1 := range data{
				logger.LogWebInfo.Debugf("指纹识别结果：%s: %s %s %s", k, v1.Name, v1.Version, v1.Description)
			}
		}
	}
}