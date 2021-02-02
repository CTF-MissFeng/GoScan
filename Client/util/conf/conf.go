package conf

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/os/gfile"
)

// 初始化写配置文件
func init(){
	data := `
# Server服务配置
[Server]
    Host = "127.0.0.1:9999" # GoScan Web服务地址
    Password = "admin888" # 用于Client同步配置所需密码，运行后请勿修改此值，否则Client同步配置信息失败

# 端口扫描配置
[PortScan]
    Enabled = true # 是否开启端口扫描功能
    Level = "all" # 日志输出级别 ALL、DEBUG、INFO、WARNING、ERROR

# 子域名扫描配置
[Domain]
    Enabled = true # 是否开启子域名扫描功能
    Level = "all" # 日志输出级别
`
	if !gfile.IsFile("./config.toml"){ // 配置文件不存在
		err := ioutil.WriteFile("config.toml", []byte(data), 0644)
		if err != nil {
			log.Fatalf("[-] 配置文件写出失败:%s", err.Error())
		}else{
			log.Fatal("[-] 检测到没有配置文件，config.toml配置文件已生成，请修改配置文件并重新运行")
		}
	}
	GetConfigInfo()
	go goGetInfo()
}

// 从web服务器接受配置信息
type Config struct{
	Nsq NsqInfo `json:"nsq"`
	PortScan PortScanInfo `json:"portscan"`
	Domain DomainInfo `json:"domain"`
	ApiKey KeyInfo `json:"apikey"`
}

// Nsq配置
type NsqInfo struct{
	NsqHost string `json:"nsqd_host"`
	CNsqHost string `json:"cnsqd_host"`
	Time int `json:"time"`
}

// 端口扫描配置
type PortScanInfo struct{
	Verify bool `json:"verify"`
	Ping bool `json:"ping"`
	Retries int `json:"retries"`
	Rate int `json:"rate"`
	Timeout int `json:"timeout"`
	Ports string `json:"ports"`
	NmapTimeout int `json:"nmap_timeout"`
	WafNum int `json:"waf_num"`
	Detection string `json:"detection"`
	NsqTimeout int `json:"nsq_timeout"`
}

// 子域名探测配置
type DomainInfo struct{
	Timeout int `json:"timeout"`
	MaxEnumTime int `json:"max_enum_time"`
	NsqTimeout int `json:"nsq_timeout"`
}

// API 秘钥配置
type KeyInfo struct{
	Shodan string `json:"shodan"`
	Binaryedge string `json:"binaryedge"`
	CensysToken string `json:"censys_token"`
	CensysSecret string `json:"censys_secret"`
	Certspotter string `json:"certspotter"`
	GitHub string `json:"github"`
	Spyse string `json:"spyse"`
	Securitytrails string `json:"securitytrails"`
	ThreatBook string `json:"threatbook"`
	URLScan string `json:"urlscan"`
	Virustotal string `json:"virustotal"`
}

// 全局调用
var Gconf *Config

// 从Web服务器获取配置信息 初始化
func GetConfigInfo(){
	host := g.Cfg().GetString("Server.Host")
	pwd := g.Cfg().GetString("Server.Password")
	url := fmt.Sprintf("http://%s/api/client/info?pwd=%s", host, pwd)
	result,err := g.Client().Timeout(15*time.Second).Get(url)
	if err != nil {
		log.Fatal("同步配置信息失败,请检查能否访问Web服务器")
	}
	defer func(){
		if result != nil{
			result.Close()
		}
	}()
	j, err := gjson.DecodeToJson(result.ReadAllString())
	if err != nil{
		log.Fatalf("同步配置信息失败,配置信息解析失败:%s",err.Error())
	}
	if err := j.Struct(&Gconf); err != nil {
		log.Fatalf("同步配置信息失败,配置信息反序列化失败:%s",err.Error())
	}
	log.Println("[+] 同步配置信息成功")
}

// 创建一个协程 用于不间断的更新配置信息
func goGetInfo(){
	time.Sleep(time.Duration(Gconf.Nsq.Time)*time.Minute)
	host := g.Cfg().GetString("Server.Host")
	pwd := g.Cfg().GetString("Server.Password")
	url := fmt.Sprintf("http://%s/api/client/info?pwd=%s", host, pwd)
	result,err := g.Client().Timeout(15*time.Second).Get(url)
	if err != nil {
		return
	}
	defer func(){
		if result != nil{
			result.Close()
		}
	}()
	j, err := gjson.DecodeToJson(result.ReadAllString())
	if err != nil{
		return
	}
	if err := j.Struct(&Gconf); err != nil {
		return
	}
	log.Printf("[+] 同步配置信息成功,下一次在[%d]分钟后更新", Gconf.Nsq.Time)
}