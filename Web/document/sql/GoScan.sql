
/*用户users表*/
DROP TABLE IF EXISTS "users";
CREATE TABLE "users"(
    "id" SERIAL PRIMARY KEY,
    "username" varchar(20) NOT NULL UNIQUE,
    "password" varchar(200) NOT NULL,
    "nick_name" varchar(100),
    "phone" varchar(20),
    "email" varchar(100),
    "remark" text,
    "create_at" timestamp DEFAULT NULL,
    "update_at" timestamp DEFAULT NULL
);

/*用户登录ip锁定表*/
DROP TABLE IF EXISTS "user_ip";
CREATE TABLE "user_ip"(
    "id" SERIAL PRIMARY KEY,
    "ip" varchar(50) NOT NULL UNIQUE,
    "lock" int, /*登录失败次数*/
    "create_at" timestamp DEFAULT NULL,
    "update_at" timestamp DEFAULT NULL
);

/*用户登录日志表*/
DROP TABLE IF EXISTS "user_log";
CREATE TABLE "user_log"(
    "id" SERIAL PRIMARY KEY,
    "username" varchar(20) NOT NULL,
    "ip" varchar(50) NOT NULL,
    "user_agent" text,
    "create_at" timestamp DEFAULT NULL,
    "update_at" timestamp DEFAULT NULL
);

/*用户操作记录表*/
DROP TABLE IF EXISTS "user_operation";
CREATE TABLE "user_operation"(
    "id" SERIAL PRIMARY KEY,
    "username" varchar(20) NOT NULL,
    "ip" varchar(50) NOT NULL,
    "theme" text NOT NULL,
    "content" text NOT NULL,
    "create_at" timestamp DEFAULT NULL
);

/*存储各种API秘钥配置信息表*/
DROP TABLE IF EXISTS "api_key";
CREATE TABLE "api_key"(
    "id" SERIAL PRIMARY KEY,
    "key" text NOT NULL UNIQUE,
    "value" text NOT NULL ,
    "create_at" timestamp DEFAULT NULL
);

/*存储子域名扫描任务*/
DROP TABLE IF EXISTS "util_subdomain_task";
CREATE TABLE "util_subdomain_task"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null UNIQUE,
    "domain_num" int not null,
    "scan_num" int not null ,
    "create_at" timestamp DEFAULT NULL
);

/*Util 存储子域名扫描结果表*/
DROP TABLE IF EXISTS "util_subdomain_result";
CREATE TABLE "util_subdomain_result"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "domain" varchar(200) not null,
    "subdomain" varchar(500) not null,
    "ip" varchar(200) not null,
    "cname" varchar(200),
    "cdn" bool,
    "location" text,
    "flag" bool,
    "nsq_flag" bool,
    "create_at" timestamp DEFAULT NULL
);

/*存储端口扫描任务*/
DROP TABLE IF EXISTS "util_portscan_task";
CREATE TABLE "util_portscan_task"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" text not null UNIQUE,
    "host_num" int not null,
    "scan_num" int not null ,
    "create_at" timestamp DEFAULT NULL
);

/*存储端口扫描结果表*/
DROP TABLE IF EXISTS "util_portscan_result";
CREATE TABLE "util_portscan_result"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" text not null,
    "host" varchar(30) not null,
    "port" int,
    "service_name" text,
    "vendor_product" text,
    "version" text,
    "flag" bool not null, /*是否接受到返回消息*/
    "nsq_flag" bool not null, /*是否已投递消息*/
    "http_flag" bool,
    "url" text,
    "code" int,
    "title" text,
    "create_at" timestamp DEFAULT NULL
);

/*厂商管理*/
DROP TABLE IF EXISTS "scan_home";
CREATE TABLE "scan_home"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null UNIQUE,
    "cus_remark" text not null,
    "create_at" timestamp DEFAULT NULL
);

/*主域名管理*/
DROP TABLE IF EXISTS "scan_domain";
CREATE TABLE "scan_domain"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "domain" varchar(200) not null UNIQUE,
    "icp_number" varchar(60),
    "flag" bool not null, /*是否接受到返回消息*/
    "nsq_flag" bool not null, /*是否已投递消息*/
    "create_at" timestamp DEFAULT NULL
);

/*子域名表*/
DROP TABLE IF EXISTS "scan_subdomain";
CREATE TABLE "scan_subdomain"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "domain" varchar(200) not null,
    "subdomain" varchar(500) not null,
    "ip" varchar(200) not null,
    "cname" varchar(200),
    "cdn" bool,
    "location" text,
    "flag" bool not null, /*是否接受到返回消息*/
    "nsq_flag" bool not null, /*是否已投递消息*/
    "create_at" timestamp DEFAULT NULL
);

/*端口表*/
DROP TABLE IF EXISTS "scan_port";
CREATE TABLE "scan_port"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "host" varchar(30) not null,
    "port" int,
    "service_name" text,
    "vendor_product" text,
    "version" text,
    "flag" bool not null, /*是否接受到返回消息*/
    "nsq_flag" bool not null, /*是否已投递消息*/
    "http_flag" bool,
    "url" text,
    "code" int,
    "title" text,
    "create_at" timestamp DEFAULT NULL
);

/*存储指纹表*/
DROP TABLE IF EXISTS "banalyze";
CREATE TABLE "banalyze"(
    "id" SERIAL PRIMARY KEY,
    "key" text NOT NULL UNIQUE,
    "description" text NOT NULL,
    "value" text NOT NULL,
    "create_at" timestamp DEFAULT NULL
);