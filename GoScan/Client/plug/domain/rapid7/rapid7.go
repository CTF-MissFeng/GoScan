package rapid7

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/CTF-MissFeng/GoScan/Client/util/logger"

	"github.com/Cgboal/SonarSearch/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type CrobatClient struct {
	conn   *grpc.ClientConn
	client proto.CrobatClient
}

func NewCrobatClient() (*CrobatClient,error) {
	config := &tls.Config{}
	conn, err := grpc.Dial("crobat-rpc.omnisint.io:443", grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		logger.LogDomain.Warningf("rapid7查询,GRPC初始化失败:%s", err.Error())
		return nil, err
	}
	client := proto.NewCrobatClient(conn)
	return &CrobatClient{
		conn:   conn,
		client: client,
	}, nil
}

func (c *CrobatClient)GetSubdomains(domain string) ([]string,error) {
	defer c.conn.Close()
	logger.LogDomain.Debug("开始进行rapid7查询子域名")

	query := &proto.QueryRequest{
		Query: domain,
	}
	stream, err := c.client.GetSubdomains(context.Background(), query)
	if err != nil{
		return nil,err
	}
	subDomains := make([]string, 0)
	for {
		str1, err := stream.Recv()
		if err != nil {
			break
		}
		subDomains = append(subDomains, str1.Domain)
	}
	if len(subDomains) == 0{
		return nil,errors.New("未发现子域名")
	}
	logger.LogDomain.Debugf("Rapid7查询共计[%d]个", len(subDomains))
	return subDomains,nil
}