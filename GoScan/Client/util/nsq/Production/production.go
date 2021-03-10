package Production

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CTF-MissFeng/GoScan/Client/util/conf"

	"github.com/gogf/gf/encoding/gbase64"
	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/frame/g"
)

// 往topic中投递消息
func SendTopicMessages(topicName string, data interface{})error{
	sendStr,err := gjson.New(data).ToJsonString()
	if err != nil {
		return err
	}
	msgStr := gbase64.EncodeString(sendStr)
	Url := fmt.Sprintf("http://%s/pub?topic=%s", conf.Gconf.Nsq.NsqHttp, topicName)
	resp,err := g.Client().Post(Url, msgStr)
	defer func(){
		if resp != nil{
			resp.Close()
		}
	}()
	if err != nil {
		return err
	}
	if strings.Contains(resp.ReadAllString(), "OK"){
		return nil
	}else{
		return errors.New(fmt.Sprintf("Pub消息失败:%s", resp.ReadAllString()))
	}
}
