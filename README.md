# GoScan
> GoScan是采用Golang语言编写的一款分布式综合资产管理系统，Web端负责展示数据和接受输入，Client端负责任务运行。

> Demo：http://112.74.169.239:9999/   test/admin888@A

> 下载地址：https://github.com/CTF-MissFeng/GoScan/releases

### 一、项目特点
> 往往在开发此类工具时，需要调用各种不同的三方工具(python、java、go)等语言编写好的资产搜集工具，调用时通过fork进程启动资产搜集工具，对于执行效率、部署都不太友好。

> 本项目所有模块均为Go开发：(子域名探测、端口扫描及指纹识别、web爬虫、web指纹识别、web漏洞扫描、服务漏洞破解等等)，只需要执行Client即可，不需要其他依赖环境，分布式docker部署方便。

> 分布式简单：通过golang语言编写的nsq消息队列进行分布式调度，排除了如redis、其它大型的MQ环境（本项目只有三个可执行文件：web、nsq、client）

### 二、模块介绍

- 子域名探测：使用rapid7源和被动搜索(30余个接口)、web主动爬虫寻找子域名、多个dns源探测、识别CDN等

- 端口扫描：自写的端口扫描及指纹识别，速度比nmap+masscan块，加上waf识别及空间探测结果

- web探测：主动爬虫搜集js、url、子域名、敏感信息等

- web指纹：提供web页面自编写web指纹

- web漏洞扫描等等模块：待开发中

### 三、部署教程
> 以ubuntu系统为例

#### 1、Web端

```bash
# 1、Postgresql数据库安装
$ apt-get install postgresql postgresql-client # 安装数据库
$ su postgres
$ psql -U postgres     # 默认安装密码为空
$ ALTER USER postgres WITH PASSWORD 'xxxxxx';     # 修改postgre用户数据库密码
$ CREATE DATABASE goscan;     # 创建数据库
$ \q    # 退出

# 2、sql文件导入，使用数据库管理工具或命令行导入sql文件

# 3、Nsq消息队列运行，防火墙开放以下端口
$ nohub ./nsqd -tcp-address 本机IP:4150 -http-address 本机IP:4151 -max-msg-timeout 1h > nsq.log &

# 4、config.toml编辑，配置数据库、web、nsq

# 5、运行web
$ nohub ./Web > web.log &

# 6、浏览器打开web，进入到扫描引擎中进行配置
```

#### 2、Client端

```bash
# 1、配置config.toml

# 2、运行Client或使用docker编译运行多个Client

$ nohub ./Client  # 单独运行

# docker编译成images，启动多个实例（Client、config.toml、Dockerfile三个文件单独放一个目录进行编译）
$ docker build -t goscan:v1 .
$ docker run -itd --name scan1 goscan:v1
$ docker run -itd --name scan2 goscan:v1
$ docker run -itd --name scan3 goscan:v1
```

### 四、项目截图
![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/1.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/2.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/3.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/4.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/5.png)

### 五、开发进度

2021.02.09

```
1、修复分布式任务执行超时问题

2、分布式结果反馈使用http提交
```

2021.02.04

```
1、修复致命错误：nsq生产者断线重连

2、web探测加入主动爬虫模块，进行二次搜集子域名；敏感信息搜集、url、js等文件链接收集

3、web探测加入截图功能，使用谷歌无头浏览器进行驱动，由web端进行
```

2021.02.1

```
1、更换web框架，不使用gin框架

2、优化端口扫描、新增子域名探测模块、web指纹探测模块(所有模块都为go写，不调用三方组件)

3、web指纹探测模块 指纹规则为json格式，支持自定义添加

4、添加扫描引擎，配置信息统一下发到客户端

5、消息队列nsq采用两组，避免消息流过大及单点故障

6、新增综合扫描（一条龙服务）
```

2021.01.03

```
1、Web框架整体完成：

后台管理：用户登录、添加用户、登录锁定、删除用户、日志管理、消息通知设置（邮件、server酱）等

实用功能：杀毒进程检测、分布式端口扫描

2、客户端：

端口扫描：采用golang开发端口扫描器（Syn探测+精简服务指纹库）
```
