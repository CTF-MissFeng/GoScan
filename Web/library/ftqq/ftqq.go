package ftqq

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"Web/app/model"

	"github.com/gogf/gf/frame/g"
)

// FtqqSend Service酱发送消息
func FtqqSend (r *model.ApiUserFtqqReq) error {
	url := fmt.Sprintf("https://sc.ftqq.com/%s.send", r.Sckey)
	data := fmt.Sprintf("text=%s&desp=%s", r.Title, r.Content)
	result,err := g.Client().Timeout(10*time.Second).Post(url, data)
	defer func(){
		if result != nil{
			result.Close()
		}
	}()
	if err != nil {
		return errors.New(fmt.Sprintf("Server酱消息发送失败:%s", err.Error()))
	}
	if !strings.Contains(result.ReadAllString(), "success"){
		return errors.New("Server酱消息发送失败,请检查提交的内容是否正确")
	}else{
		return nil
	}
}
