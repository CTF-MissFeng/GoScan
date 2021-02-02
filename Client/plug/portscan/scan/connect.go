package scan

import (
	"fmt"
	"net"
	"time"

	"Client/util/logger"
)

// ConnectVerify 使用Connect方式二次校检Sync扫描出的端口
func ConnectVerify(host string, port int, timeout int) (bool, int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false, 0
	}
	logger.LogPortScan.Debugf("[+] 二次验证 %s:%d 开放", host, port)
	conn.Close()
	return true, port
}
