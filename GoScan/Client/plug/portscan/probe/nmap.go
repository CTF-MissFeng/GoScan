package probe

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/CTF-MissFeng/GoScan/Client/plug/portscan/probe/statik"
	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/axgle/mahonia"
	"github.com/gogf/gf/encoding/ghtml"
	"github.com/gogf/gf/text/gregex"
	"github.com/parnurzeal/gorequest"
	"github.com/rakyll/statik/fs"
	"github.com/saintfish/chardet"
)

type NmapProbe struct{
	Probes []*Probe
	ProbesMapKName map[string]*Probe // 以探针名为key对应Probe
	Services map[int]string // 保存端口对应的指纹
}

type Probe struct {
	Name string     // 探针名称
	Ports []map[string]string    // 该探针默认端口
	Data []byte     // socket发送的数据
	Fallback string // 如果探针匹配项没有匹配到，则使用Fallback指定的探针作为备用
	Matchs []*Match // 正则协议内容
	Rarity int // 指纹探测等级
}

type Match struct {
	IsSoft bool
	Service     string
	Pattern     string
	VersionInfo string
	PatternCompiled *regexp.Regexp
}

// 定义探针probe说明字段
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

// 探针匹配成功解析数据
type Extras struct {
	ServiceNmae     string
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
	Sign            string
	StatusCode      int
	ServiceURL      string
}

// 全局调用
var Gnmaps  *NmapProbe

// 初始化nmap
func NewNmap(){
	nmap := NmapProbe{}
	nmap.Init()
	Gnmaps = &nmap
}

// nmap指纹库初始化
func (N *NmapProbe)Init(){
	statikFS, err := fs.New()
	if err != nil {
		logger.LogPortScan.Fatalf("[-] 静态资源FS初始化失败:%s", err.Error())
	}
	resources, err := statikFS.Open("/nmap.txt")
	if err != nil{
		logger.LogPortScan.Fatalf("[-] 加载Nmap协议失败:%s", err.Error())
	}
	defer resources.Close()

	nmapContents, err := ioutil.ReadAll(resources)
	if err != nil{
		logger.LogPortScan.Fatalf("[-] 加载Nmap协议失败:%s", err.Error())
	}

	resources1, err := statikFS.Open("/port.txt")
	if err != nil{
		logger.LogPortScan.Fatalf("[-] 加载端口数据失败:%s\n", err.Error())
	}
	defer resources1.Close()
	nmapContentsPort, err := ioutil.ReadAll(resources1)
	if err != nil{
		logger.LogPortScan.Fatalf("[-] 加载端口数据失败:%s\n", err.Error())
	}

	strdata := string(nmapContents)
	N.parseProbesFromContent(&strdata)  // 解析nmap指纹库
	N.parseProbesToMapKName()
	N.ServiceParse(nmapContentsPort) // 解析端口对应协议数据
	logger.LogPortScan.Debugf("[+] 指纹加载成功，共计[%d]个探针,[%d]条正则,[%d]条TCP端口指纹", len(N.Probes), N.Count(), len(N.Services))
}

// 统计指纹库中正则条数
func (N *NmapProbe) Count()int{
	count := 0
	for _, probe := range N.Probes{
		count += len(probe.Matchs)
	}
	return count
}

// 将probe变成key-value形式, 方便后面进行备用探针匹配
func (N *NmapProbe) parseProbesToMapKName() {
	var probesMap = map[string]*Probe{}
	for _, probe := range N.Probes {
		probesMap[probe.Name] = probe
	}
	N.ProbesMapKName = probesMap
}

// 解析nmap指纹库
func (N *NmapProbe) parseProbesFromContent(content *string) {
	var probes []*Probe
	var lines []string
	linesTemp := strings.Split(*content, "\n")

	// 过滤掉规则文件中的注释和空行
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	if len(lines) == 0 {
		logger.LogPortScan.Fatalf("[-] [端口扫描] nmap指纹库数据为空\n")
	}

	// 判断指纹库中是否只有一个Exclude标识符
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		if c > 1 {
			logger.LogPortScan.Fatalf("[-] [端口扫描] nmap指纹库格式错误，只能有一个Exclude标识符，且该标识符应该在首行")
		}
	}

	// 判断nmap指纹库首行格式
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		logger.LogPortScan.Fatalf("[-] [端口扫描] nmap指纹库解析失败，首行应该由Probe或Exclude标识符开始")
	}

	// 去除首行Exclude标识符
	if c == 1 {
		lines = lines[1:]
	}

	// 剩下的都是有效的指纹库数据，重新拼接数据
	content1 := strings.Join(lines, "\n")
	content1 = "\n" + content1
	//WriteProbe(content1)
	probeParts := strings.Split(content1, "\nProbe") // 以探针Probe标识进行分割
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		probe.fromString(&probePart)
		probes = append(probes, &probe)
	}
	N.Probes = probes
}

// 解析每段探针probe标识符数据
func (p *Probe) fromString(data *string){
	data1 := strings.TrimSpace(*data)
	lines := strings.Split(data1, "\n")
	probeStr := lines[0]

	// 解析探针Probe开头信息
	p.parseProbeInfo(probeStr)

	var matchs []*Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, &match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, &softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		}  else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		}
	}
	p.Matchs = matchs
}

// 解析探针Probe开头信息
func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]
	if !(proto == "TCP " || proto == "UDP ") {
		logger.LogPortScan.Fatalf("[-] [端口扫描] 解析nmap指纹库失败，protocol字段必须为TCP或UDP")
	}
	if len(other) == 0 {
		logger.LogPortScan.Fatalf("[-] [端口扫描] 解析nmap指纹库失败，探测名称描述字段名为空")
	}
	directive := p.getDirectiveSyntax(other)
	p.Name = directive.DirectiveName
	dataList := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(dataList) > 0{
		data_byte, err := DecodeData(dataList[0])
		if err != nil{
			logger.LogPortScan.Fatalf("[-] [端口扫描] nmap指纹库编码发送包失败[%s]:  %s\n", dataList[0], err)
		}else{
			p.Data = data_byte
		}
	}
}

// 解析 Probe 说明字段  Probe TCP RTSPRequest q|OPTIONS / RTSP/1.0\r\n\r\n|
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1: blankIndex+2]
	delimiter := data[blankIndex+2: blankIndex+3]
	directiveStr := data[blankIndex+3:]
	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr
	return directive
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

// 解析协议的默认端口
func (p *Probe) parsePorts(data string) {
	data1 := strings.Replace(data,"ports","",-1)
	if strings.Contains(data1, ","){ // 是否为多个端口
		strlist := strings.Split(data1, ",")
		for _,v := range strlist {
			p.Ports = append(p.Ports, map[string]string{v:""})
		}
	}else{
		p.Ports = []map[string]string{{data1:""}}
	}
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(string(data[len("rarity")+1:]))
}

// 解析探针数据包
func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// socket发送探测数据包编码
func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// respone正则判断
func (N *NmapProbe)regxRespone(response []byte, matchtmp []*Match, Fallback string)(bool, *Extras){
	extras := Extras{}
	if len(response) > 0 {
		for _, match := range matchtmp { // 循环匹配该协议中的正则表达式
			matched := match.MatchPattern(response)
			if matched && !match.IsSoft {
				extras = match.ParseVersionInfo(response)
				extras.ServiceNmae = match.Service
				return true, &extras
			}
		}
		if _, ok := N.ProbesMapKName[Fallback]; ok { // 进行贪婪匹配
			fbProbe := N.ProbesMapKName[Fallback]
			for _, match := range fbProbe.Matchs {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras = match.ParseVersionInfo(response)
					extras.ServiceNmae = match.Service
					return true, &extras
				}
			}
		}
	}
	return false, &extras
}

// 正则匹配respone内容
func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

// 正则匹配respone成功，取出相应的内容
func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

// 进行socket连接发送数据
func (N *NmapProbe) grabResponse(addr string, Indexes, SocketTimeout int) ([]byte, error) {
	var response []byte // 保存响应的结果
	connTimeout := time.Duration(int64(SocketTimeout))*time.Second // 设置socket连接超时时间
	conn, errConn := net.DialTimeout("tcp", addr, connTimeout)
	defer func(){
		if conn != nil{
			conn.Close()
		}
	}()

	if errConn != nil { // 连接端口失败
		return nil, errConn
	}

	if len(N.Probes[Indexes].Data) > 0 { // 发送指纹探测数据
		conn.SetWriteDeadline(time.Now().Add(time.Second*time.Duration(int64(SocketTimeout))))
		_, errWrite := conn.Write(N.Probes[Indexes].Data)
		if errWrite != nil {
			return nil, errWrite
		}
	}

	conn.SetReadDeadline(time.Now().Add(time.Second*time.Duration(int64(SocketTimeout))))
	for true {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return nil, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return response, nil
}

// 解析常见端口协议
func(N *NmapProbe)ServiceParse(data []byte){
	linesTemp := strings.Split(string(data), "\n")
	servicesmap := make(map[int]string, 0)
	for _, tmp := range linesTemp{
		if strings.Index(tmp, "/") == -1{
			continue
		}
		tmplist := strings.Split(tmp, "\t")
		if len(tmplist) >= 2{
			tmplist2 := strings.Split(tmplist[1], "/")
			prope := strings.Trim(tmplist2[1], "")
			if prope == "tcp" || prope == "TCP"{
				port,_ := strconv.Atoi(strings.Trim(tmplist2[0],""))
				servicesmap[port] = strings.Trim(tmplist[0],"")
			}
		}
	}
	N.Services = servicesmap
}

// 定义返回结果
type Task struct{
	Addr string
	ServiceNmae string
	ProbeName string
	VendorProduct string
	Version string
	Url string
	StatusCode int
	Title string
}

// 常规服务直接返回，不进行指纹探测
func DefaultProbes(port string)string{
	var defaults = make(map[string]string, 0)
	defaults["80"] = "http"
	defaults["443"] = "https"
	defaults["3306"] = "mysql"
	defaults["21"] = "ftp"
	defaults["23"] = "telnet"
	if v,ok := defaults[port]; ok{
		return v
	}else{
		return ""
	}
}

// 单端口 指纹探测
func (N *NmapProbe) ScanWithProbe(host, port string, SocketTimeout int, resultChan chan *Task){
	// 节约探测时间，常规端口不探测直接返回
	v := DefaultProbes(port)
	if v != ""{
		tasktmp := Task{}
		tasktmp.Addr = GetAddress(host, port)
		tasktmp.ServiceNmae = v
		N.HttpCheck(&tasktmp, SocketTimeout)
		resultChan <- &tasktmp
		return
	}

	var defaultProbe []int // 保存默认端口对应的协议索引
	var oneProbe []int // 保存优先级为一对应的协议索引
	var sixProbe []int // 保存优先级小于6对应的协议索引
	var nineProbe []int // 保存剩余对应的协议索引
	var excludeIndex []int // 保存排除的协议索引

	for i := 0; i < len(N.Probes); i++{
		// 组合默认端口对应协议
		for _,v := range N.Probes[i].Ports{
			_,ok := v[port]
			if ok{
				defaultProbe = append(defaultProbe, i)
				excludeIndex = append(excludeIndex, i)
				break
			}
		}
		// 组合优先级为一的协议
		if N.Probes[i].Rarity == 1 && !isexclude(excludeIndex,i){
			oneProbe = append(oneProbe, i)
		}
		// 组合优先级小于6的协议
		if N.Probes[i].Rarity !=1 && N.Probes[i].Rarity <6 && !isexclude(excludeIndex,i){
			sixProbe = append(sixProbe, i)
		}
		// 组合剩余的协议
		if N.Probes[i].Rarity >= 6 && !isexclude(excludeIndex,i){
			nineProbe = append(nineProbe, i)
		}
	}


	// 优先并发探测默认端口的协议
	if len(defaultProbe) > 0{
		wg := sync.WaitGroup{}
		chanTask := make(chan *Task, len(defaultProbe))
		for _,i := range defaultProbe{
			wg.Add(1)
			go func(v int){
				defer wg.Done()
				N.taskSocket(GetAddress(host, port), v, SocketTimeout, chanTask)
			}(i)
		}
		wg.Wait()
		close(chanTask)
		for resp := range chanTask {
			logger.LogPortScan.Debugf("[+] 默认端口指纹获取成功:%s:%s %s", host, port, resp.ServiceNmae)
			N.HttpCheck(resp, SocketTimeout)
			resultChan <- resp
			return
		}
	}

	// 并发探测等级为1的协议
	if len(oneProbe) > 0{
		wg := sync.WaitGroup{}
		chanTask := make(chan *Task, len(oneProbe))
		for _,i := range oneProbe{
			wg.Add(1)
			go func(v int){
				defer wg.Done()
				N.taskSocket(GetAddress(host, port), v, SocketTimeout, chanTask)
			}(i)
		}
		wg.Wait()
		close(chanTask)
		for resp := range chanTask {
			logger.LogPortScan.Debugf("[+] 级别1指纹获取成功:%s:%s %s", host, port, resp.ServiceNmae)
			N.HttpCheck(resp, SocketTimeout)
			resultChan <- resp
			return
		}
	}

	// 并发探测等级小于6的协议
	if len(sixProbe) > 0{
		wg := sync.WaitGroup{}
		chanTask := make(chan *Task, len(sixProbe))
		for _,i := range sixProbe{
			wg.Add(1)
			go func(v int){
				defer wg.Done()
				N.taskSocket(GetAddress(host, port), v, SocketTimeout, chanTask)
			}(i)
		}
		wg.Wait()
		close(chanTask)
		for resp := range chanTask {
			logger.LogPortScan.Debugf("[+] 级别<6指纹获取成功:%s:%s %s", host, port, resp.ServiceNmae)
			N.HttpCheck(resp, SocketTimeout)
			resultChan <- resp
			return
		}
	}

	// 并发探测剩下等级的协议
	if len(nineProbe) > 0{
		wg := sync.WaitGroup{}
		chanTask := make(chan *Task, len(nineProbe))
		for _,i := range nineProbe{
			wg.Add(1)
			go func(v int){
				defer wg.Done()
				N.taskSocket(GetAddress(host, port), v, SocketTimeout, chanTask)
			}(i)
		}
		wg.Wait()
		close(chanTask)
		for resp := range chanTask {
			logger.LogPortScan.Debugf("[+] 级别<9指纹获取成功:%s:%s %s", host, port, resp.ServiceNmae)
			N.HttpCheck(resp, SocketTimeout)
			resultChan <- resp
			return
		}
	}

	// 若未识别出指纹，则按照默认端口对应的指纹返回
	ServiceNmae,ok := N.ServiceFind(port)
	if ok{
		logger.LogPortScan.Debugf("[-] 指纹探测失败:%s:%s %s", host, port, ServiceNmae)
		tasktmp := Task{}
		tasktmp.Addr = GetAddress(host, port)
		tasktmp.ServiceNmae = ServiceNmae
		N.HttpCheck(&tasktmp, SocketTimeout)
		resultChan <- &tasktmp
		return
	}else{
		logger.LogPortScan.Debugf("[-] 未知服务:%s:%s", host, port)
		tasktmp := Task{}
		tasktmp.Addr = GetAddress(host, port)
		resultChan <- &tasktmp
		return
	}

}

// 判断元素是否存在
func isexclude(m []int, value int) bool{
	if len(m) == 0{
		return false
	}
	for _,v := range m{
		if v == value{
			return true
		}
	}
	return false
}

// 组合host
func GetAddress(ip, port string)string{
	return ip + ":" + port
}

// 识别端口服务指纹
func (N *NmapProbe)taskSocket(address string, Indexes, SocketTimeout int, taskChan chan *Task){
	responeData,err := N.grabResponse(address, Indexes, SocketTimeout)
	if err != nil { // 端口发送指纹失败
		return
	}
	ok,extras := N.regxRespone(responeData, N.Probes[Indexes].Matchs, N.Probes[Indexes].Fallback)
	if !ok{ // 指纹识别失败
		return
	}
	taskChan <- &Task{
		Addr: address,
		ServiceNmae: extras.ServiceNmae,
		ProbeName: N.Probes[Indexes].Name,
		VendorProduct: extras.VendorProduct,
		Version: extras.Version,
	}
}

// 返回默认端口对应的指纹
func(N *NmapProbe)ServiceFind(port string)(string,bool){
	portint,_ := strconv.Atoi(port)
	vaule, ok := N.Services[portint]
	if ok{
		return vaule + "?", true
	}else{
		return "",false
	}
}

// web服务探测
func(N *NmapProbe)HttpCheck(task *Task, timeout int){
	if !strings.Contains(task.ServiceNmae, "http") && !strings.Contains(task.ServiceNmae, "ssl"){
		return
	}
	// http服务探测
	var url = ""
	if strings.Contains(task.ServiceNmae, "http") && !strings.Contains(task.ServiceNmae, "https"){
		url = fmt.Sprintf("http://%s", task.Addr)
	}else{
		url = fmt.Sprintf("https://%s", task.Addr)
	}
	SendHttp(url, timeout, task)
}

// 发送HTTP数据包
func SendHttp(url string, timeout int, task *Task){
	resp, body, err := gorequest.New().
				Get(url).
				Timeout(time.Duration(int64(timeout))*time.Second).
				TLSClientConfig(&tls.Config{ InsecureSkipVerify: true}).
				AppendHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").
				AppendHeader("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 11) AppleWebKit/538.41 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36").
				End()
	if err != nil{
		return
	}
	task.Url = url
	task.StatusCode = resp.StatusCode
	task.Title = getTitle(body)
}

// 获取网页标题
func getTitle(s string)string{
	list,err := gregex.MatchString("<title>(.*?)</title>", s)
	if err != nil{
		return ""
	}
	if len(list) == 0{
		return ""
	}
	title := list[len(list)-1]
	detector:=chardet.NewTextDetector()
	char,err := detector.DetectBest([]byte(title)) // 检测编码类型
	if err != nil{
		return ""
	}
	if char.Charset == "UTF-8"{
		return ghtml.SpecialChars(title)
	}
	return ConvertToString(ghtml.SpecialChars(title),"GBK", "utf-8")
}

// 编码转换成utf-8编码
func ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}