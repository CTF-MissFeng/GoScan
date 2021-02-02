package smtp

import (
	"Web/app/model"

	"github.com/gogf/gf/encoding/gjson"
	"github.com/gogf/gf/util/gconv"
	"gopkg.in/gomail.v2"
)

// 校检Smtp账户密码等是否正确
func SendMailConnect(r *model.ApiUserSendMailReq) error {
	mail, err := gomail.NewDialer(r.Host, gconv.Int(r.Port), r.Username, r.Password).Dial()
	if err != nil{
		return err
	}
	defer func() {
		if mail != nil{
			mail.Close()
		}
	}()
	return nil
}

// 发送邮件
func SendMail(s string, r *model.ApiUserSendMaiTitleReq) error {
	j := gjson.New(s)
	mail := gomail.NewDialer(gconv.String(j.Get("Host")),gconv.Int(j.Get("Port")),
		gconv.String(j.Get("Username")),gconv.String(j.Get("Password")))
	mail1, err := mail.Dial()
	if err != nil{
		return err
	}

	defer func() {
		if mail != nil{
			mail1.Close()
		}
	}()
	m := gomail.NewMessage()
	m.SetHeader("From", gconv.String(j.Get("Sender")))
	m.SetHeader("To", r.Address)
	m.SetHeader("Subject", r.Title)
	m.SetBody("text/html", r.Content)
	err = mail.DialAndSend(m)
	return err
}