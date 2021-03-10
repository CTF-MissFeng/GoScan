package subscraping

import (
	"context"
	"net/http"
	"regexp"
)

// BasicAuth 请求的授权标头
type BasicAuth struct {
	Username string
	Password string
}

// Source 是每个被动源继承的接口
type Source interface {
	Run(context.Context, string, *Session) <-chan Result
	// Name 返回源名称
	Name() string
}

// 会话是传递给源的选项
type Session struct {
	// Extractor 是为每个域创建的子域的正则表达式
	Extractor *regexp.Regexp
	// Keys 应用程序的API密钥
	Keys *Keys
	// Client 当前的http客户端
	Client *http.Client
}

// Keys 包含我们存储的当前API密钥
type Keys struct {
	Binaryedge           string   `json:"binaryedge"`
	CensysToken          string   `json:"censysUsername"`
	CensysSecret         string   `json:"censysPassword"`
	Certspotter          string   `json:"certspotter"`
	Chaos                string   `json:"chaos"`
	DNSDB                string   `json:"dnsdb"`
	GitHub               []string `json:"github"`
	IntelXHost           string   `json:"intelXHost"`
	IntelXKey            string   `json:"intelXKey"`
	PassiveTotalUsername string   `json:"passivetotal_username"`
	PassiveTotalPassword string   `json:"passivetotal_password"`
	Recon                string   `json:"recon"`
	Robtex               string   `json:"robtex"`
	Securitytrails       string   `json:"securitytrails"`
	Shodan               string   `json:"shodan"`
	Spyse                string   `json:"spyse"`
	ThreatBook           string   `json:"threatbook"`
	URLScan              string   `json:"urlscan"`
	Virustotal           string   `json:"virustotal"`
	ZoomEyeUsername      string   `json:"zoomeye_username"`
	ZoomEyePassword      string   `json:"zoomeye_password"`
}

// Result 源返回的结果结构
type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

// ResultType 源返回的结果类型
type ResultType int

// 源返回的结果类型
const (
	Subdomain ResultType = iota
	Error
)
