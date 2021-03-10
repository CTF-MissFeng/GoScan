package nsq

var (
	PortScanTopic = "PortScan" // 端口扫描任务 Topic
	PortScanTopicChanl = "Nmap" // 端口扫描任务 消费者

	RPortScanTopic = "RPortScan" // 端口扫描结果 Topic
	RPortScanChanl = "Server" // 端口扫描结果 消费者

	SubDomainTopic = "SubDomain" // 子域名扫描任务 Topic
	SubDomainChanl = "subdomain" // 子域名扫描任务 消费者

	RSubDomainTopic = "RSubDomain" // 子域名扫描结果 Topic
	RSubDomainChanl = "Server" // 子域名扫描结果 消费者

	WebInfoTopic = "WebInfo" // web探测 Topic
	WebInfoChanl = "webinfo" // web探测 Chanl

	RWebInfoTopic = "RWebInfo" // web探测结果 Topic
	RWebInfoChanl = "Server" // web探测结果 Chanl
)


// 端口扫描返回格式
type ResponsePortScanStruct struct{
	CusName string `json:"cus_name"`
	Host string `json:"host"`
	Port string `json:"port"`
	ServiceName string `json:"service_name"`
	VendorProduct string `json:"vendor_product"`
	Version string `json:"version"`
	HttpFlag bool `json:"http_flag"`
	Url string `json:"url"`
	Code int `json:"code"`
	Title string `json:"title"`
	Flag bool `json:"flag"`
	NsqFlag bool `json:"nsq_flag"`
}

// 子域名扫描返回格式
type ResponseSubDomainStruct struct{
	CusName string `json:"cus_name"`
	Domain string `json:"domain"`
	Subdomain string `json:"subdomain"`
	Ip string `json:"ip"`
	Cname string `json:"cname"`
	Cdn bool `json:"cdn"`
	Location string `json:"location"`
	Flag bool `json:"flag"`
	NsqFlag bool `json:"nsq_flag"`
}