package subscraping

import (
	"regexp"
	"sync"
)

var subdomainExtractorMutex = &sync.Mutex{}

// NewSubdomainExtractor 创建一个新的正则表达式提取基于给定域的文本子域。
func NewSubdomainExtractor(domain string) (*regexp.Regexp, error) {
	subdomainExtractorMutex.Lock()
	defer subdomainExtractorMutex.Unlock()
	extractor, err := regexp.Compile(`[a-zA-Z0-9\*_.-]+\.` + domain)
	if err != nil {
		return nil, err
	}
	return extractor, nil
}

// Exists 判断元素是否存在
func Exists(values []string, key string) bool {
	for _, v := range values {
		if v == key {
			return true
		}
	}
	return false
}
