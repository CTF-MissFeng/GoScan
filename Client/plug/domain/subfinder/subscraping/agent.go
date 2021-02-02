package subscraping

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"Client/util/logger"
)

// NewSession 为域创建一个新的会话对象
func NewSession(domain string, keys *Keys, timeout int) (*Session, error) {
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}

	session := &Session{
		Client: client,
		Keys:   keys,
	}

	// 为当前域创建一个新的提取器对象
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

// Get 向具有扩展参数的URL发出GET请求
func (s *Session) Get(ctx context.Context, getURL, cookies string, headers map[string]string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, cookies, headers, nil, BasicAuth{})
}

// SimpleGet 向URL发出简单的GET请求
func (s *Session) SimpleGet(ctx context.Context, getURL string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, "", map[string]string{}, nil, BasicAuth{})
}

// Post 向具有扩展参数的URL发出POST请求
func (s *Session) Post(ctx context.Context, postURL, cookies string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, cookies, headers, body, BasicAuth{})
}

// SimplePost 向URL发出简单的POST请求
func (s *Session) SimplePost(ctx context.Context, postURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, "", map[string]string{"Content-Type": contentType}, body, BasicAuth{})
}

// HTTPRequest 向具有扩展参数的URL发出任何HTTP请求
func (s *Session) HTTPRequest(ctx context.Context, method, requestURL, cookies string, headers map[string]string, body io.Reader, basicAuth BasicAuth) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	if basicAuth.Username != "" || basicAuth.Password != "" {
		req.SetBasicAuth(basicAuth.Username, basicAuth.Password)
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return httpRequestWrapper(s.Client, req)
}

// DiscardHTTPResponse 按需求丢弃响应内容
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		_, err := io.Copy(ioutil.Discard, response.Body)
		if err != nil {
			logger.LogDomain.Warningf("无法丢弃响应正文: %s\n", err)
			return
		}
		response.Body.Close()
	}
}

func httpRequestWrapper(client *http.Client, request *http.Request) (*http.Response, error) {
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, fmt.Errorf("从 %s 收到意外的状态代码 %d ", requestURL,resp.StatusCode)
	}
	return resp, nil
}
