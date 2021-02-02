package ipquery

import "github.com/lionsoul2014/ip2region/binding/golang/ip2region"

// QueryIp 查询IP位置信息
func QueryIp(ip string) (*ip2region.IpInfo, error) {
	region, err := ip2region.New("public/ip/ip2region.db")
	if err != nil {
		return nil,err
	}
	defer region.Close()
	ipinfo,err := region.MemorySearch(ip)
	if err != nil {
		return nil,err
	}
	return &ipinfo, nil
}