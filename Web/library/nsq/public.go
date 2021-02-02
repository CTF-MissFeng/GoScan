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
)
