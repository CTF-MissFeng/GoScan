
/*用户users表*/
DROP TABLE IF EXISTS "users";
CREATE TABLE "users"
(
    "id"        SERIAL PRIMARY KEY,
    "username"  varchar(20)  NOT NULL UNIQUE,
    "password"  varchar(200) NOT NULL,
    "nick_name" varchar(100),
    "phone"     varchar(20),
    "email"     varchar(100),
    "remark"    text,
    "create_at" timestamp DEFAULT NULL,
)

/*用户登录ip锁定表*/
DROP TABLE IF EXISTS "user_ip";
CREATE TABLE "user_ip"(
    "id" SERIAL PRIMARY KEY,
    "ip" varchar(50) NOT NULL UNIQUE,
    "lock" int,
    "create_at" timestamp DEFAULT NULL,
);

/*用户登录日志表*/
DROP TABLE IF EXISTS "user_log";
CREATE TABLE "user_log"(
    "id" SERIAL PRIMARY KEY,
    "username" varchar(20) NOT NULL,
    "ip" varchar(50) NOT NULL,
    "user_agent" text,
    "create_at" timestamp DEFAULT NULL,
);

/*用户操作记录表*/
DROP TABLE IF EXISTS "user_operation";
CREATE TABLE "user_operation"(
    "id" SERIAL PRIMARY KEY,
    "username" varchar(20) NOT NULL,
    "ip" varchar(50) NOT NULL,
    "theme" varchar(200) NOT NULL,
    "content" text NOT NULL,
    "create_at" timestamp DEFAULT NULL
);

/*存储各种API秘钥配置信息表*/
DROP TABLE IF EXISTS "api_key";
CREATE TABLE "api_key"(
    "id" SERIAL PRIMARY KEY,
    "key" varchar(50) NOT NULL UNIQUE,
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
    "ip" varchar(50) not null,
    "cname" text,
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
    "cus_name" varchar(200) not null UNIQUE,
    "host_num" int not null,
    "scan_num" int not null ,
    "create_at" timestamp DEFAULT NULL
);

/*存储端口扫描结果表*/
DROP TABLE IF EXISTS "util_portscan_result";
CREATE TABLE "util_portscan_result"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "host" varchar(50) not null,
    "port" int,
    "service_name" varchar(30),
    "vendor_product" varchar(200),
    "version" varchar(100),
    "flag" bool,
    "nsq_flag" bool,
    "http_flag" bool,
    "url" varchar(500),
    "code" int,
    "title" varchar(500),
    "create_at" timestamp DEFAULT NULL
);

/*存储指纹表*/
DROP TABLE IF EXISTS "banalyze";
CREATE TABLE "banalyze"(
    "id" SERIAL PRIMARY KEY,
    "key" varchar(200) NOT NULL UNIQUE,
    "description" varchar(200) NOT NULL,
    "value" text NOT NULL,
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
    "flag" bool,
    "nsq_flag" bool,
    "create_at" timestamp DEFAULT NULL
);

/*子域名表*/
DROP TABLE IF EXISTS "scan_subdomain";
CREATE TABLE "scan_subdomain"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "domain" varchar(200) not null,
    "subdomain" varchar(500) not null UNIQUE,
    "ip" varchar(200) not null,
    "cname" varchar(200),
    "cdn" bool,
    "location" text,
    "flag" bool,
    "nsq_flag" bool,
    "create_at" timestamp DEFAULT NULL
);

/*端口表*/
DROP TABLE IF EXISTS "scan_port";
CREATE TABLE "scan_port"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "host" varchar(50) not null,
    "port" int,
    "service_name" varchar(30),
    "vendor_product" varchar(200),
    "version" varchar(100),
    "flag" bool,
    "nsq_flag" bool,
    "http_flag" bool,
    "url" text,
    "code" int,
    "title" text,
    "crack_flag" bool,
    "crack_nsq_flag" bool,
    "scan_flag" bool,
    "scan_nsq_flag" bool,
    "create_at" timestamp DEFAULT NULL
);

/*存储web探测表*/
DROP TABLE IF EXISTS "scan_web";
CREATE TABLE "scan_web"(
    "id" SERIAL PRIMARY KEY,
    "cus_name" varchar(200) not null,
    "url" varchar(500) NOT NULL UNIQUE,
    "code" int NOT NULL,
    "title" varchar(500),
    "content_length" int,
    "fingerprint" text,
    "image" varchar(200),
    "screenshot_flag" bool,
    "js" text,
    "urls" text,
    "forms" text,
    "secret" text,
    "flag" bool,
    "nsq_flag" bool,
    "scan_flag" bool,
    "scan_nsq_flag" bool,
    "create_at" timestamp DEFAULT NULL
);