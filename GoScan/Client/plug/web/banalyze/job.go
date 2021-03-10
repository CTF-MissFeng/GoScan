package banalyze

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	URL "net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/parnurzeal/gorequest"
)

// resultApp 指纹识别结果
type ResultApp struct {
	Name       string   `json:"name"`
	Version    []string	`json:"version"`
	Implies    []string `json:"implies"`
	Description string  `json:"description"`
}

// Analyze 进行指纹识别
func (wapp *Wappalyzer) Analyze(url string, timeout int)(map[string]*ResultApp, error){
	u, err := URL.Parse(url) // 判断url格式是否正确
	if err != nil{
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	jobURL := u.String()
	// 发送http请求
	resp, body, err1 := gorequest.New().
		Get(jobURL).
		Timeout(time.Duration(int64(timeout))*time.Second).
		TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
		AppendHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		AppendHeader("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/538.41 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").End()
	if err1 != nil{
		return nil,err1[0]
	}
	detectedApplications := make(map[string]*ResultApp) // 定义保存指纹识别结果变量

	// 创建dom解析器
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}

	// 解析respone的cookie
	cookiesMap := make(map[string]string)
	for _, cookie := range resp.Header["set-cookie"] {
		keyValues := strings.Split(cookie, ";")
		for _, keyValueString := range keyValues {
			keyValueSlice := strings.Split(keyValueString, "=")
			if len(keyValueSlice) > 1 {
				cookiesMap[keyValueSlice[0]] = keyValueSlice[1]
			}
		}
	}


	// 遍历指纹规则进行匹配
	for _, app := range wapp.Apps {
		versions := make([]string,0) // 保存匹配到的version信息
		tmpFlag := false // 是否匹配成功标识
		tmp1Flag := make([]bool,0) // and条件匹配

		// jump判断
		if len(app.Jump) != 0{
			for _,path := range app.Jump{
				res,err2 := AnalyzeJump(jobURL+"/"+path, timeout, app)
				if err2 != nil{
					continue
				}
				if len(res) == 0{
					continue
				}
				for key := range res{
					if _,ok := detectedApplications[key]; !ok{
						detectedApplications[key] = res[key]
					}
				}
			}
		}
		// html匹配
		if len(app.HTMLRegex) != 0{
			if ok, v := findMatches(body, app.HTMLRegex); ok{
				tmpFlag = true
				tmp1Flag = append(tmp1Flag, true)
				if len(v) != 0{
					versions = append(versions, v...)
				}
			}else{
				tmp1Flag = append(tmp1Flag, false)
			}
		}
		// header匹配
		if len(app.HeaderRegex) != 0{
			if ok,v := findInHeaders(resp.Header, app.HeaderRegex); ok {
				tmpFlag = true
				tmp1Flag = append(tmp1Flag, true)
				if len(v) != 0{
					versions = append(versions, v...)
				}
			}else{
				tmp1Flag = append(tmp1Flag, false)
			}
		}
		// Url匹配
		if len(app.URLRegex) != 0{
			if ok,v := findMatches(jobURL, app.URLRegex); ok{
				tmpFlag = true
				tmp1Flag = append(tmp1Flag, true)
				if len(v) != 0{
					versions = append(versions, v...)
				}
			}else{
				tmp1Flag = append(tmp1Flag, false)
			}
		}
		// script tags匹配
		if len(app.ScriptRegex) != 0{
			doc.Find("script").Each(func(i int, s *goquery.Selection) {
				if script, exists := s.Attr("src"); exists {
					if ok,v := findMatches(script, app.ScriptRegex); ok{
						tmpFlag = true
						tmp1Flag = append(tmp1Flag, true)
						if len(v) != 0{
							versions = append(versions, v...)
						}
					}
				}
			})
		}
		// meta tags匹配
		if len(app.MetaRegex) != 0{
			for _, h := range app.MetaRegex {
				selector := fmt.Sprintf("meta[name='%s']", h.Name)
				doc.Find(selector).Each(func(i int, s *goquery.Selection) {
					content, _ := s.Attr("content")
					if ok,v := findMatches(content, []AppRegexp{h}); ok{
						tmpFlag = true
						tmp1Flag = append(tmp1Flag, true)
						if len(v) != 0{
							versions = append(versions, v...)
						}
					}
				})
			}
		}
		// cookies匹配
		for _, c := range app.CookieRegex {
			if _, ok1 := cookiesMap[c.Name]; ok1 {
				if c.Regexp != nil {
					if ok, v := findMatches(cookiesMap[c.Name], []AppRegexp{c}); ok {
						tmpFlag = true
						tmp1Flag = append(tmp1Flag, true)
						if len(v) != 0{
							versions = append(versions, v...)
						}
					}else{
						tmp1Flag = append(tmp1Flag, false)
					}
				}
			}else{
				tmp1Flag = append(tmp1Flag, false)
			}
		}

		if app.Flag{
			tmp1 := true
			for _,v := range tmp1Flag{
				if !v{
					tmp1 = false
				}
			}
			if tmp1{
				detectedApplications[app.Name] = &ResultApp{
					Name: app.Name,
					Version: versions,
					Implies: app.Implies,
					Description: app.Description,
				}
			}
		}else if tmpFlag{
			detectedApplications[app.Name] = &ResultApp{
				Name: app.Name,
				Version: versions,
				Implies: app.Implies,
				Description: app.Description,
			}
		}
	}
	return detectedApplications, nil
}

// findMatches 进行正则表达式匹配
func findMatches(content string, regexes []AppRegexp) (bool, []string) {
	var version []string
	var flag bool

	for _, r := range regexes {
		matches := r.Regexp.FindAllStringSubmatch(content, -1)
		if matches == nil {
			continue
		}
		flag = true
		if r.Version != "" {
			if v := findVersion(matches, r.Version); v != ""{
				if r.Name == ""{
					version = append(version, v)
				}else{
					version = append(version, r.Name+": "+v)
				}
			}
		}
	}
	return flag, version
}

// findVersion 解析版本
func findVersion(matches [][]string, version string) string {
	var v string
	for _, matchPair := range matches {
		for i := 1; i <= 3; i++ {
			bt := fmt.Sprintf("\\%v", i)
			if strings.Contains(version, bt) && len(matchPair) >= i {
				v = strings.Replace(version, bt, matchPair[i], 1)
			}
		}
		if v != "" {
			return v
		}
	}
	return ""
}

// findInHeaders 匹配header头
func findInHeaders(headers http.Header, regexes []AppRegexp) (bool, []string) {
	var version []string
	var flag bool

	for _, hre := range regexes {
		if headers.Get(hre.Name) == "" {
			continue
		}
		hk := http.CanonicalHeaderKey(hre.Name)
		for _, headerValue := range headers[hk] {
			if headerValue == "" {
				continue
			}
			ok, v := findMatches(headerValue, []AppRegexp{hre})
			if ok && len(v) != 0{
				version = append(version, v...)
			}
			if ok{
				flag = true
			}
		}
	}
	return flag, version
}

// AnalyzeJump 进行指纹识别
func AnalyzeJump(url string, timeout int, app *App)(map[string]*ResultApp, error){
	u, err := URL.Parse(url) // 判断url格式是否正确
	if err != nil{
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	jobURL := u.String()
	// 发送http请求
	resp, body, err1 := gorequest.New().
		Get(jobURL).
		Timeout(time.Duration(int64(timeout))*time.Second).
		TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
		AppendHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
		AppendHeader("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/538.41 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").End()
	if err1 != nil{
		return nil,err1[0]
	}
	detectedApplications := make(map[string]*ResultApp) // 定义保存指纹识别结果变量

	// 创建dom解析器
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}

	// 解析respone的cookie
	cookiesMap := make(map[string]string)
	for _, cookie := range resp.Header["set-cookie"] {
		keyValues := strings.Split(cookie, ";")
		for _, keyValueString := range keyValues {
			keyValueSlice := strings.Split(keyValueString, "=")
			if len(keyValueSlice) > 1 {
				cookiesMap[keyValueSlice[0]] = keyValueSlice[1]
			}
		}
	}

	versions := make([]string,0) // 保存匹配到的version信息
	tmpFlag := false // 是否匹配成功标识
	tmp1Flag := make([]bool,0) // and条件匹配

	// html匹配
	if len(app.HTMLRegex) != 0{
		if ok, v := findMatches(body, app.HTMLRegex); ok{
			tmpFlag = true
			tmp1Flag = append(tmp1Flag, true)
			if len(v) != 0{
				versions = append(versions, v...)
			}
		}else{
			tmp1Flag = append(tmp1Flag, false)
		}
	}
	// header匹配
	if len(app.HeaderRegex) != 0{
		if ok,v := findInHeaders(resp.Header, app.HeaderRegex); ok {
			tmpFlag = true
			tmp1Flag = append(tmp1Flag, true)
			if len(v) != 0{
				versions = append(versions, v...)
			}
		}else{
			tmp1Flag = append(tmp1Flag, false)
		}
	}
	// Url匹配
	if len(app.URLRegex) != 0{
		if ok,v := findMatches(jobURL, app.URLRegex); ok{
			tmpFlag = true
			tmp1Flag = append(tmp1Flag, true)
			if len(v) != 0{
				versions = append(versions, v...)
			}
		}else{
			tmp1Flag = append(tmp1Flag, false)
		}
	}
	// script tags匹配
	if len(app.ScriptRegex) != 0{
		doc.Find("script").Each(func(i int, s *goquery.Selection) {
			if script, exists := s.Attr("src"); exists {
				if ok,v := findMatches(script, app.ScriptRegex); ok{
					tmpFlag = true
					tmp1Flag = append(tmp1Flag, true)
					if len(v) != 0{
						versions = append(versions, v...)
					}
				}else{
					tmp1Flag = append(tmp1Flag, false)
				}
			}
		})
	}
	// meta tags匹配
	if len(app.MetaRegex) != 0{
		for _, h := range app.MetaRegex {
			selector := fmt.Sprintf("meta[name='%s']", h.Name)
			doc.Find(selector).Each(func(i int, s *goquery.Selection) {
				content, _ := s.Attr("content")
				if ok,v := findMatches(content, []AppRegexp{h}); ok{
					tmpFlag = true
					tmp1Flag = append(tmp1Flag, true)
					if len(v) != 0{
						versions = append(versions, v...)
					}
				}else{
					tmp1Flag = append(tmp1Flag, false)
				}
			})
		}
	}
	// cookies匹配
	for _, c := range app.CookieRegex {
		if _, ok1 := cookiesMap[c.Name]; ok1 {
			if c.Regexp != nil {
				if ok, v := findMatches(cookiesMap[c.Name], []AppRegexp{c}); ok {
					tmpFlag = true
					tmp1Flag = append(tmp1Flag, true)
					if len(v) != 0{
						versions = append(versions, v...)
					}
				}else{
					tmp1Flag = append(tmp1Flag, false)
				}
			}
		}else{
			tmp1Flag = append(tmp1Flag, false)
		}
	}

	if app.Flag{
		tmp1 := true
		for _,v := range tmp1Flag{
			if !v{
				tmp1 = false
			}
		}
		if tmp1{
			detectedApplications[app.Name] = &ResultApp{
				Name: app.Name,
				Version: versions,
				Implies: app.Implies,
				Description: app.Description,
			}
		}
	}else if tmpFlag{
		detectedApplications[app.Name] = &ResultApp{
			Name: app.Name,
			Version: versions,
			Implies: app.Implies,
			Description: app.Description,
		}
	}
	return detectedApplications, nil
}