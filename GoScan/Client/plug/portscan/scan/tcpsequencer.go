package scan

import (
	"math"
	"sync/atomic"
)

// TCPSequencer TCP序列号
type TCPSequencer struct {
	current uint32
}

// NewTCPSequencer 创建TCP序列号
func NewTCPSequencer() *TCPSequencer {
	return &TCPSequencer{current: math.MaxUint32}
}

// Next 返回下一个TCP序列号
func (t *TCPSequencer) Next() uint32 {
	value := atomic.AddUint32(&t.current, 1) // 增加
	return value
}