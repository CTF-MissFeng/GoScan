package gospider

import (
	"regexp"
	"strings"
)

const SUBRE = `(?i)(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+` // 子域名正则
var nameStripRE = regexp.MustCompile("(?i)^((20)|(25)|(2b)|(2f)|(3d)|(3a)|(40))+")

// subdomainRegex
func subdomainRegex(domain string) *regexp.Regexp {
	d := strings.Replace(domain, ".", "[.]", -1)
	return regexp.MustCompile(SUBRE + d)
}

// GetSubdomains 根据正则表达式匹配子域名
func GetSubdomains(source, domain string) []string {
	var subs []string
	re := subdomainRegex(domain)
	for _, match := range re.FindAllStringSubmatch(source, -1) {
		subs = append(subs, CleanSubdomain(match[0]))
	}
	return subs
}

func CleanSubdomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = cleanName(s)
	return s
}

func cleanName(name string) string {
	for {
		if i := nameStripRE.FindStringIndex(name); i != nil {
			name = name[i[1]:]
		} else {
			break
		}
	}
	name = strings.Trim(name, "-")
	if len(name) > 1 && name[0] == '.' {
		name = name[1:]
	}
	return name
}