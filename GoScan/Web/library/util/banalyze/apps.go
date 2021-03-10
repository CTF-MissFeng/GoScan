package banalyze

import (
	"encoding/json"
	"regexp"
	"strings"
)

// AppRegexp 存放解析后的正则表达式
type AppRegexp struct {
	Name    string
	Regexp  *regexp.Regexp
	Version string
}

type StringArray []string

// App 解析存放单个web指纹规则
type App struct {
	Cookies  map[string]string `json:"cookies"`
	Headers  map[string]string `json:"headers"`
	Meta     map[string]string `json:"meta"`
	HTML     StringArray       `json:"html"`
	Script   StringArray       `json:"script"`
	URL      StringArray       `json:"url"`

	Name     string 			`json:"name"`
	Website  string            `json:"website"`
	Implies  StringArray       `json:"implies"`
	Jump     StringArray	   `json:"jump"`
	Description string 		   `json:"description"`
	Flag 	 bool 			   `json:"flag"`

	HTMLRegex   []AppRegexp `json:"-"`
	ScriptRegex []AppRegexp `json:"-"`
	URLRegex    []AppRegexp `json:"-"`
	HeaderRegex []AppRegexp `json:"-"`
	MetaRegex   []AppRegexp `json:"-"`
	CookieRegex []AppRegexp `json:"-"`
}

// Wappalyzer 解析整个web指纹规则
type Wappalyzer struct {
	Apps	   []*App
}

// LoadApps 解析指纹
func LoadApps(r []byte) (*Wappalyzer, error) {
	wapp := &Wappalyzer{}
	if err := json.Unmarshal(r, &wapp.Apps); err != nil{
		return nil,err
	}
	for i, v := range wapp.Apps {
		app := v
		app.HTMLRegex = compileRegexes(v.HTML)
		app.ScriptRegex = compileRegexes(v.Script)
		app.URLRegex = compileRegexes(v.URL)

		app.HeaderRegex = compileNamedRegexes(app.Headers)
		app.MetaRegex = compileNamedRegexes(app.Meta)
		app.CookieRegex = compileNamedRegexes(app.Cookies)
		wapp.Apps[i] = app
	}
	return wapp,nil
}

func compileNamedRegexes(from map[string]string) []AppRegexp {
	var list []AppRegexp
	for key, value := range from {
		h := AppRegexp{
			Name: key,
		}
		if value == "" {
			value = ".*"
		}
		splitted := strings.Split(value, "\\;")
		r, err := regexp.Compile(splitted[0])
		if err != nil {
			continue
		}
		if len(splitted) > 1 && strings.HasPrefix(splitted[1], "version:") {
			h.Version = splitted[1][8:]
		}
		h.Regexp = r
		list = append(list, h)
	}
	return list
}

func compileRegexes(s StringArray) []AppRegexp {
	var list []AppRegexp
	for _, regexString := range s {
		splitted := strings.Split(regexString, "\\;")
		regex, err := regexp.Compile(splitted[0])
		if err != nil {
			continue
		} else {
			rv := AppRegexp{
				Regexp: regex,
			}
			if len(splitted) > 1 && strings.HasPrefix(splitted[1], "version") {
				rv.Version = splitted[1][8:]
			}
			list = append(list, rv)
		}
	}
	return list
}