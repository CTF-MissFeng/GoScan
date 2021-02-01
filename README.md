# GoScan
> GoScan是采用Golang语言编写的一款分布式综合资产管理系统，适合红队、SRC等使用。

### 一、开发进度

2021.02.1

```
1、更换web框架，不使用gin框架
2、优化端口扫描、新增子域名探测模块、web指纹探测模块(所有模块都为go写，不调用三方组件)
3、添加扫描引擎，配置信息统一下发到客户端
4、消息队列nsq采用两组，避免消息流过大及单点故障
5、新增综合扫描（一条龙服务）
```

2021.01.03

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
