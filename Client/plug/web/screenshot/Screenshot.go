package screenshot

import (
	"context"
	"io/ioutil"
	"math"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type Config struct {
	Timeout int // 超时设置
	Buffer []byte // 保存截图数据
	Url string
	Context    context.Context
	CtxCancel  context.CancelFunc
}

// 开始运行截图
func (cfg *Config)Run() error{
	cfg.Context, _ = chromedp.NewContext(context.Background()) // 创建chromedp上下文,第一次运行在该浏览器上创建一个新选项卡。否则，其第一次运行将分配一个新的浏览器
	cfg.Context, cfg.CtxCancel = context.WithTimeout(cfg.Context, time.Duration(cfg.Timeout)*time.Second) // 设置上下文超时
	defer cfg.CtxCancel()
	return cfg.exec()
}

func (cfg *Config) exec() error{
	if err := chromedp.Run(cfg.Context, screenshot(cfg.Url, 90, &cfg.Buffer));  err != nil {
		return err
	}
	if err := ioutil.WriteFile("123.png", cfg.Buffer, 0644); err != nil {
		return err
	}
	return nil
}

// screenshot 官方示例截全图  quality为图片质量
func screenshot(url string, quality int64, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, contentSize, err := page.GetLayoutMetrics().Do(ctx)
			if err != nil {
				return err
			}

			width, height := int64(math.Ceil(contentSize.Width)), int64(math.Ceil(contentSize.Height))

			err = emulation.SetDeviceMetricsOverride(width, height, 1, false).
				WithScreenOrientation(&emulation.ScreenOrientation{
					Type:  emulation.OrientationTypePortraitPrimary,
					Angle: 0,
				}).
				Do(ctx)
			if err != nil {
				return err
			}

			*res, err = page.CaptureScreenshot().
				WithQuality(quality).
				WithClip(&page.Viewport{
					X:      contentSize.X,
					Y:      contentSize.Y,
					Width:  contentSize.Width,
					Height: contentSize.Height,
					Scale:  1,
				}).Do(ctx)
			if err != nil {
				return err
			}

			return nil
		}),
	}
}