package producer

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CTF-MissFeng/GoScan/Web/app/model"
	"github.com/CTF-MissFeng/GoScan/Web/library/logger"
	Gnsq "github.com/CTF-MissFeng/GoScan/Web/library/nsq"

	"github.com/gogf/gf/frame/g"
	"github.com/nsqio/go-nsq"
)

// 全局变量，其他包调用生产者
var NnsqProducer *nsq.Producer

// 定义解析nsqd-stats结构体
type statJson struct {
	Version   string `json:"version"`
	Health    string `json:"health"`
	StartTime int    `json:"start_time"`
	Topics    []struct {
		TopicName string `json:"topic_name"`
		Channels  []struct {
			ChannelName   string `json:"channel_name"`
			Depth         int    `json:"depth"`
			BackendDepth  int    `json:"backend_depth"`
			InFlightCount int    `json:"in_flight_count"`
			DeferredCount int    `json:"deferred_count"`
			MessageCount  int    `json:"message_count"`
			RequeueCount  int    `json:"requeue_count"`
			TimeoutCount  int    `json:"timeout_count"`
			ClientCount   int    `json:"client_count"`
			Clients       []struct {
				ClientID                      string `json:"client_id"`
				Hostname                      string `json:"hostname"`
				Version                       string `json:"version"`
				RemoteAddress                 string `json:"remote_address"`
				State                         int    `json:"state"`
				ReadyCount                    int    `json:"ready_count"`
				InFlightCount                 int    `json:"in_flight_count"`
				MessageCount                  int    `json:"message_count"`
				FinishCount                   int    `json:"finish_count"`
				RequeueCount                  int    `json:"requeue_count"`
				ConnectTs                     int64    `json:"connect_ts"`
				SampleRate                    int    `json:"sample_rate"`
				Deflate                       bool   `json:"deflate"`
				Snappy                        bool   `json:"snappy"`
				UserAgent                     string `json:"user_agent"`
				TLS                           bool   `json:"tls"`
				TLSCipherSuite                string `json:"tls_cipher_suite"`
				TLSVersion                    string `json:"tls_version"`
				TLSNegotiatedProtocol         string `json:"tls_negotiated_protocol"`
				TLSNegotiatedProtocolIsMutual bool   `json:"tls_negotiated_protocol_is_mutual"`
			} `json:"clients"`
			Paused               bool `json:"paused"`
			E2EProcessingLatency struct {
				Count       int         `json:"count"`
				Percentiles interface{} `json:"percentiles"`
			} `json:"e2e_processing_latency"`
		} `json:"channels"`
		Depth                int  `json:"depth"`
		BackendDepth         int  `json:"backend_depth"`
		MessageCount         int  `json:"message_count"`
		MessageBytes         int64  `json:"message_bytes"`
		Paused               bool `json:"paused"`
		E2EProcessingLatency struct {
			Count       int         `json:"count"`
			Percentiles interface{} `json:"percentiles"`
		} `json:"e2e_processing_latency"`
	} `json:"topics"`
	Memory struct {
		HeapObjects       int `json:"heap_objects"`
		HeapIdleBytes     int `json:"heap_idle_bytes"`
		HeapInUseBytes    int `json:"heap_in_use_bytes"`
		HeapReleasedBytes int `json:"heap_released_bytes"`
		GcPauseUsec100    int `json:"gc_pause_usec_100"`
		GcPauseUsec99     int `json:"gc_pause_usec_99"`
		GcPauseUsec95     int `json:"gc_pause_usec_95"`
		NextGcBytes       int `json:"next_gc_bytes"`
		GcTotalRuns       int `json:"gc_total_runs"`
	} `json:"memory"`
	Producers []struct {
		ClientID      string `json:"client_id"`
		Hostname      string `json:"hostname"`
		Version       string `json:"version"`
		RemoteAddress string `json:"remote_address"`
		State         int    `json:"state"`
		ReadyCount    int    `json:"ready_count"`
		InFlightCount int    `json:"in_flight_count"`
		MessageCount  int    `json:"message_count"`
		FinishCount   int    `json:"finish_count"`
		RequeueCount  int    `json:"requeue_count"`
		ConnectTs     int    `json:"connect_ts"`
		SampleRate    int    `json:"sample_rate"`
		Deflate       bool   `json:"deflate"`
		Snappy        bool   `json:"snappy"`
		UserAgent     string `json:"user_agent"`
		PubCounts     []struct {
			Topic string `json:"topic"`
			Count int    `json:"count"`
		} `json:"pub_counts"`
		TLS                           bool   `json:"tls"`
		TLSCipherSuite                string `json:"tls_cipher_suite"`
		TLSVersion                    string `json:"tls_version"`
		TLSNegotiatedProtocol         string `json:"tls_negotiated_protocol"`
		TLSNegotiatedProtocolIsMutual bool   `json:"tls_negotiated_protocol_is_mutual"`
	} `json:"producers"`
}

// 获取指定topic的Nsqd stats接口信息
func NsqStatsInfo(topic string)(*statJson,error){
	url := fmt.Sprintf("http://%s/stats?format=json&topic=%s", g.Cfg().GetString("nsq.HttpHost"), topic)
	respone,err := g.Client().Timeout(10*time.Second).Get(url)
	defer func(){
		if respone != nil{
			respone.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	jsondata := statJson{}
	if err = json.Unmarshal(respone.ReadAll(), &jsondata); err != nil{
		return nil, err
	}
	return &jsondata, nil
}

// 清空指定topic消息
func NsqTopicEmpty(topicName, channelName string)error{
	url := fmt.Sprintf("http://%s/channel/empty?topic=%s&channel=%s",g.Cfg().GetString("nsq.HttpHost"),topicName, channelName)
	url1 := fmt.Sprintf("http://%s/topic/empty?topic=%s",g.Cfg().GetString("nsq.HttpHost"),topicName)
	response1,_ := g.Client().Timeout(8*time.Second).Post(url)
	respone,err := g.Client().Timeout(8*time.Second).Post(url1)
	defer func(){
		if respone != nil{
			respone.Close()
		}
		if response1 != nil{
			response1.Close()
		}
	}()
	if err != nil{
		return err
	}
	return nil
}

// 初始化Nsq生产者
func NsqInitProducer(){
	config := nsq.NewConfig()
	producer, err := nsq.NewProducer(g.Cfg().GetString("nsq.TcpHost"), config)
	if err != nil{
		logger.WebLog.Fatalf("[-] [生产者] 连接消息队列服务失败:%s", err.Error())
	}
	if err = producer.Ping(); err != nil{
		logger.WebLog.Fatalf("[-] [生产者] 连接消息队列服务失败:%s", err.Error())
	}
	logger.WebLog.Infof("[+] [生产者] 连接消息队列成功")
	NnsqProducer = producer
}

// 往topic中投递消息
func SendTopicMessages(topicName string, msg []byte){
	if err := NnsqProducer.Ping(); err != nil{
		headerNsq()
	}
	err := NnsqProducer.Publish(topicName, msg)
	if err != nil{
		logger.WebLog.Warningf("[-] [生产者] topic:%s 投递消息失败:%s", topicName, err.Error())
		time.Sleep(3*time.Second)
		SendTopicMessages(topicName, msg)
	}
}

// 防止nsq掉线，重新连接
func headerNsq(){
	for{
		config := nsq.NewConfig()
		producer, err := nsq.NewProducer(g.Cfg().GetString("nsq.TcpHost"), config)
		if err != nil{
			logger.WebLog.Debugf("[-] [生产者] 重新连接消息队列服务失败:%s", err.Error())
			time.Sleep(2*time.Second)
			continue
		}
		if err = producer.Ping(); err != nil{
			logger.WebLog.Debugf("[-] [生产者] 重新连接消息队列服务失败:%s", err.Error())
			time.Sleep(2*time.Second)
			continue
		}
		logger.WebLog.Infof("[+] [生产者] 重新连接消息队列成功")
		NnsqProducer = producer
		break
	}
}

// 子域名扫描 投递消息到消息队列
func PubSubDomain(r []model.ScanDomainApiAddReq){
	for _, v := range r{
		network := bytes.Buffer{}
		enc := gob.NewEncoder(&network)
		err := enc.Encode(&v)
		if err != nil{
			logger.WebLog.Warningf("[-] [子域名投递消息] gob序列化数据失败:%s", err.Error())
			continue
		}
		SendTopicMessages(Gnsq.SubDomainTopic, network.Bytes())
		time.Sleep(100*time.Millisecond) // 延时下，防止太快push不上
	}
}

// 端口扫描 投递消息到消息队列
func PortScanSendMessage(r []model.UtilPortScanApiAddReq){
	for _, v := range r{
		network := bytes.Buffer{}
		enc := gob.NewEncoder(&network)
		err := enc.Encode(&v)
		if err != nil{
			logger.WebLog.Warningf("[-] [端口扫描投递消息] gob序列化数据失败:%s", err.Error())
			continue
		}
		SendTopicMessages(Gnsq.PortScanTopic, network.Bytes())
		time.Sleep(100*time.Millisecond) // 延时下，防止太快push不上
	}
}

// web探测 投递消息到消息队列
func PubWebInfo(r []model.NsqPushWeb){
	for _, v := range r{
		network := bytes.Buffer{}
		enc := gob.NewEncoder(&network)
		err := enc.Encode(&v)
		if err != nil{
			logger.WebLog.Warningf("[-] [web探测投递消息] gob序列化数据失败:%s", err.Error())
			continue
		}
		SendTopicMessages(Gnsq.WebInfoTopic, network.Bytes())
		time.Sleep(100*time.Millisecond) // 延时下，防止太快push不上
	}
}