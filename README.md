# GoScan
> GoScan是采用Golang语言编写的一款分布式综合资产管理系统，适合红队、SRC等使用。

### 一、项目说明
> 演示地址：http://112.74.169.239/     test/admin888


### 二、部署教程
> golang编译成二进制文件，所以部署是非常方便。

#### Web端
> 推荐Linux系统运行，所以只编译了Linux系统的文件，服务端部署条件只需要postgresql数据库即可

```bash
# 以ubuntu为例，照顾小白

# 数据库安装：

$ apt-get install postgresql postgresql-client # 安装数据库
$ su postgres
$ psql -U postgres     # 默认安装密码为空
$ ALTER USER postgres WITH PASSWORD 'xxxxxx';     # 修改postgre用户数据库密码
$ CREATE DATABASE goscan;     # 创建数据库
$ \q    # 退出

# Nsq消息队列服务运行：

$ chmod +x nsqd
# Nsqd的http服务只允许本机访问，TCP服务外网开放，请设置防火墙或云主机策略开放TCP端口
$ nohup ./nsqd -http-address 127.0.0.1:8081 -tcp-address 0.0.0.0:8082 > nsq.log 2>&1 &

# Web端运行：

$ chmod +x GoScan
$ ./GoScan      # 第一次运行会释放配置文件就结束运行
$ vim config.yaml     # 编辑配置文件,设置相应参数值：web端host和port、数据库配置、Nsqd配置等
$ ./GoScan    # 配置完成，运行看是否成功
$ nohup ./GoScan > web.log 2>&1 &       # 若运行成功则进行后台运行

# 浏览器访问该web地址，默认账户密码：admin/123456789，登录后修改密码

```

> 示例yaml配置
```yaml
# web服务配置
ServerInfo:
host: "0.0.0.0"
port: 80
# 设置Gin运行模式：release(生产)、debug(调试)、test(测试)
mode: "release"

# Postgresql数据库配置
PostgresqlInfo:
dbName: "goscan"
userName: "postgres"
passWord: "123456"
host: "127.0.0.1"
port: "5432"

# JWT认证配置
AuthInfo:
# 过期时间：9999分钟
jwtExpire: 30
# JWT秘钥，上线后请更改此值
secretKey: "password"

# Nsqd配置
NsqInfo:
# Nsqd http服务请不要对外开放,保持127.0.0.1即可
host: "127.0.0.1"
port: "8081"
# Nsqd TCP服务 对外开放  IP地址设置为本机网卡ip地址
TcpHost: "0.0.0.0"
TcpPort: "8082"
```



#### Client端

> **注意**，请设置linux最大打开文件数，如 `ulimit -u 65535`，否则扫描提不上速。

> **重点**：端口扫描需要pacp组件，安装了nmap会自带，若未安装则安装pacp或nmap都行

```bash
$ ./Client    # 第一次运行会释放配置文件，请修改配置文件中的Nsqd消息队列服务器地址和TCP端口
$ vim config.yaml
$ ./Clinet   # 若正常运行则进入后台运行
$ nohup ./Clinet &
```


### 三、开发进度

1. 2021.01.03

```
1、Web框架整体完成：

后台管理：用户登录、添加用户、登录锁定、删除用户、日志管理、消息通知设置（邮件、server酱）等

实用功能：杀毒进程检测、分布式端口扫描

2、客户端：

端口扫描：采用golang开发端口扫描器（Syn探测+精简服务指纹库）
```

### 四、演示

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/1.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/2.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/3.png)

![index](https://github.com/CTF-MissFeng/GoScan/blob/main/doc/4.png)
