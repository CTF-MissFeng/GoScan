package public

// 端口扫描所需参数
type Options struct {
	CusName       string // 任务名
	Verify         bool // 是否二次验证端口扫描结果
	Ping           bool // 是否存活探测
	Debug          bool // 是否显示端口扫描debug信息
	Retries           int    // 端口重试次数
	Rate              int    // 端口扫描速率
	Timeout           int    // 端口扫描超时时间
	Hosts              string `json:"Hosts"`// 扫描目标
	Ports             string // 扫描的端口
	NmapTimeout    int // 指纹识别socket连接超时
	WafNum 	   int `json:"WafNum"`// 探测出端口超过多少数量直接丢弃（WAF干扰）
	Detection	   string // 优先扫描 先探测常规端口，若存活则探测指定端口
}

// 全局调用
var GOptions *Options