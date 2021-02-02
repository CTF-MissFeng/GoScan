package icp

import (
	"errors"
	"fmt"
	"time"

	"Web/app/dao"
	"Web/app/model"
	"Web/library/logger"
	"Web/library/nsq/producer"

	"github.com/anaskhan96/soup"
	"github.com/gogf/gf/frame/g"
)

// ICP查询
func IcpQuery(domain string)(string,error){
	url := fmt.Sprintf("http://icp.chinaz.com/%s", domain)
	respone,err := g.Client().Timeout(10*time.Second).Get(url)
	defer func() {
		if respone != nil{
			respone.Close()
		}
	}()
	if err != nil {
		return "",err
	}
	doc := soup.HTMLParse(respone.ReadAllString())
	root := doc.FindAll("font")
	if len(root) == 0{
		return "",errors.New("未找到ICP备案号")
	}
	return root[0].Text(),nil
}

// 添加到数据库中
func InsertDomain(cusName string,data []string){
	for _,domain := range data{
		icp,err := IcpQuery(domain)
		if err != nil {
			_,err = dao.ScanDomain.Insert(g.Map{
				"CusName": cusName,
				"Domain": domain,
				"Flag": false,
				"NsqFlag": false,
			})
			if err != nil {
				logger.WebLog.Warningf("添加主域名 插入数据库错误:%s", err.Error())
				continue
			}
		}else{
			_,err = dao.ScanDomain.Insert(g.Map{
				"CusName": cusName,
				"Domain": domain,
				"IcpNumber": icp,
				"Flag": false,
				"NsqFlag": false,
			})
			if err != nil {
				logger.WebLog.Warningf("添加主域名 插入数据库错误:%s", err.Error())
				continue
			}
		}
	}
	// 投递子域名扫描消息
	result, err := dao.ScanDomain.Where("nsq_flag=?",false).FindAll()
	if err != nil{
		logger.WebLog.Warningf("子域名投递消息  数据库错误:%s", err.Error())
		return
	}
	if result == nil || len(result) == 0{
		return
	}
	pubMessages := make([]model.NsqPushDomain,0)
	for _,v := range result{
		pubMessages = append(pubMessages, model.NsqPushDomain{CusName: v.CusName, Domain: v.Domain})
	}
	_,err = dao.ScanDomain.Where("1=?",1).Update(g.Map{"nsq_flag":true})
	if err != nil {
		logger.WebLog.Warningf("子域名投递消息  修改主域名状态失败:%s", err.Error())
		return
	}
	producer.PubSubDomain(pubMessages)
}