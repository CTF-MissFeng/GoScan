package gospider

import (
    "net/url"
    "regexp"
    "strings"
)

var linkFinderRegex = regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|do|shtml|jspx)(?:[\?|#][^"|']{0,}|)))(?:"|')`)

// LinkFinder 匹配链接
func LinkFinder(source string) ([]string, error) {
    var links []string
    if len(source) > 1000000 {
        source = strings.ReplaceAll(source, ";", ";\r\n")
        source = strings.ReplaceAll(source, ",", ",\r\n")
    }
    source = DecodeChars(source)
    match := linkFinderRegex.FindAllStringSubmatch(source, -1)
    for _, m := range match {
        matchGroup1 := FilterNewLines(m[1])
        if matchGroup1 == "" {
            continue
        }
        links = append(links, matchGroup1)
    }
    links = Unique(links)
    return links, nil
}

// DecodeChars 编码字符串
func DecodeChars(s string) string {
    source, err := url.QueryUnescape(s)
    if err == nil {
        s = source
    }
    replacer := strings.NewReplacer(
        `\u002f`, "/",
        `\u0026`, "&",
    )
    s = replacer.Replace(s)
    return s
}

// FilterNewLines
func FilterNewLines(s string) string {
    return regexp.MustCompile(`[\t\r\n]+`).ReplaceAllString(strings.TrimSpace(s), " ")
}

// Unique 切片去重
func Unique(intSlice []string) []string {
    keys := make(map[string]bool)
    var list []string
    for _, entry := range intSlice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}