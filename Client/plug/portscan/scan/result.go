package scan

import "sync"

// Result 保存端口扫描结果
type Result struct {
	sync.RWMutex
	Ports map[int]struct{}
}

// NewResult 实例化Result
func NewResult() *Result {
	return &Result{Ports: make(map[int]struct{})}
}

// AddPort 添加端口
func (r *Result) AddPort(port int) {
	r.Lock()
	defer r.Unlock()

	_,ok := r.Ports[port]
	if ok{ // 端口已存在
		return
	}else{
		r.Ports[port] = struct{}{}
	}
}

// DeletePorts 清空端口数据
func (r *Result) DeletePorts(){
	r.Ports = make(map[int]struct{}) // 直接初始化比删除更节约内存
}