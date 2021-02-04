# GoScan
> GoScan是采用Golang语言编写的一款分布式综合资产管理系统，适合红队、SRC等使用。

> 该项目是自己空余时间所写，进度较慢；特公开源代码，有能力的人可以二次开发。

> 示例：http://112.74.169.239:9999/  admin/admin888@A  请不要进行增删改

### 一、开发进度

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

### 二、部署教程
> web和client端都推荐linux运行

#### web端

```
# 以ubuntu为例，照顾小白

# 1、数据库安装：

$ apt-get install postgresql postgresql-client # 安装数据库
$ su postgres
$ psql -U postgres     # 默认安装密码为空
$ ALTER USER postgres WITH PASSWORD 'xxxxxx';     # 修改postgre用户数据库密码
$ CREATE DATABASE goscan;     # 创建数据库
$ \q    # 退出

# 2、数据库导入,使用数据库管理工具连接postgresql数据库，导入项目路径下的sql文件： /Web/document/sql/GoScan.sql

# 3、Nsq消息队列服务运行，需要运行2个nsq进程，4150和4151分别用于web端push消息，和client端push消息
$ nohup ./client/nsqd -tcp-address 本机IP:4151 -http-address 127.0.0.1:10002 --data-path=./client > client.log 2>&1 &
$ nohup ./server/nsqd -max-msg-timeout 1h -tcp-address 本机ip:4150 -http-address 127.0.0.1:10001 --data-path=./server > server.log 2>&1 &

# 4、Web端运行：

$ chmod +x Web
# 编写config配置文件，参考项目中：GoScan/blob/main/Web/config/config.toml
$ ./Web    # 配置完成，运行看是否成功
$ nohup ./Web > web.log 2>&1 &       # 若运行成功则进行后台运行

# 浏览器访问该web地址，默认账户密码：admin/admin888@A，登录后修改密码
```

#### Client端

```
# config配置文件参考：GoScan/blob/main/Client/config.toml
```

### 三、演示

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/1.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/2.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/4.png)
