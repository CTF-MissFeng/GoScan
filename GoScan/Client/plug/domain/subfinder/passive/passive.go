package passive

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CTF-MissFeng/GoScan/Client/plug/domain/subfinder/subscraping"
)

// EnumerateSubdomains 枚举给定域的所有子域
func (a *Agent) EnumerateSubdomains(domain string, keys *subscraping.Keys, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		session, err := subscraping.NewSession(domain, keys, timeout)
		if err != nil {
			results <- subscraping.Result{Type: subscraping.Error, Error: fmt.Errorf("subfinder无法启动子域名会话 %s: %s", domain, err)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), maxEnumTime) // 设置超时时间

		timeTaken := make(map[string]string)
		timeTakenMutex := &sync.Mutex{}

		wg := &sync.WaitGroup{}
		for source, runner := range a.sources {
			wg.Add(1)

			now := time.Now()
			go func(source string, runner subscraping.Source) {
				for resp := range runner.Run(ctx, domain, session) {
					results <- resp
				}

				duration := time.Since(now)
				timeTakenMutex.Lock()
				timeTaken[source] = fmt.Sprintf("花费时间[%s]", duration)
				timeTakenMutex.Unlock()

				wg.Done()
			}(source, runner)
		}
		wg.Wait()

		//for source, data := range timeTaken {
		//	//logger.LogDomain.Debugf("源[%s] %s", source, data)
		//}

		close(results)
		cancel()
	}()

	return results
}
