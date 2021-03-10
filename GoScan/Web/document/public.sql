/*
 Navicat Premium Data Transfer

 Source Server         : postgresql
 Source Server Type    : PostgreSQL
 Source Server Version : 130001
 Source Host           : localhost:5432
 Source Catalog        : goscan
 Source Schema         : public

 Target Server Type    : PostgreSQL
 Target Server Version : 130001
 File Encoding         : 65001

 Date: 08/02/2021 00:18:51
*/


-- ----------------------------
-- Sequence structure for api_key_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."api_key_id_seq";
CREATE SEQUENCE "public"."api_key_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."api_key_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for banalyze_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."banalyze_id_seq";
CREATE SEQUENCE "public"."banalyze_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."banalyze_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for scan_domain_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."scan_domain_id_seq";
CREATE SEQUENCE "public"."scan_domain_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."scan_domain_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for scan_home_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."scan_home_id_seq";
CREATE SEQUENCE "public"."scan_home_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."scan_home_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for scan_port_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."scan_port_id_seq";
CREATE SEQUENCE "public"."scan_port_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."scan_port_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for scan_subdomain_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."scan_subdomain_id_seq";
CREATE SEQUENCE "public"."scan_subdomain_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."scan_subdomain_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for scan_web_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."scan_web_id_seq";
CREATE SEQUENCE "public"."scan_web_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."scan_web_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for user_ip_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."user_ip_id_seq";
CREATE SEQUENCE "public"."user_ip_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."user_ip_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for user_log_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."user_log_id_seq";
CREATE SEQUENCE "public"."user_log_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."user_log_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for user_operation_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."user_operation_id_seq";
CREATE SEQUENCE "public"."user_operation_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."user_operation_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for users_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."users_id_seq";
CREATE SEQUENCE "public"."users_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."users_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for util_portscan_result_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."util_portscan_result_id_seq";
CREATE SEQUENCE "public"."util_portscan_result_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."util_portscan_result_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for util_portscan_task_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."util_portscan_task_id_seq";
CREATE SEQUENCE "public"."util_portscan_task_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."util_portscan_task_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for util_subdomain_result_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."util_subdomain_result_id_seq";
CREATE SEQUENCE "public"."util_subdomain_result_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."util_subdomain_result_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Sequence structure for util_subdomain_task_id_seq
-- ----------------------------
DROP SEQUENCE IF EXISTS "public"."util_subdomain_task_id_seq";
CREATE SEQUENCE "public"."util_subdomain_task_id_seq" 
INCREMENT 1
MINVALUE  1
MAXVALUE 2147483647
START 1
CACHE 1;
ALTER SEQUENCE "public"."util_subdomain_task_id_seq" OWNER TO "postgres";

-- ----------------------------
-- Table structure for api_key
-- ----------------------------
DROP TABLE IF EXISTS "public"."api_key";
CREATE TABLE "public"."api_key" (
  "id" int4 NOT NULL DEFAULT nextval('api_key_id_seq'::regclass),
  "key" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "value" text COLLATE "pg_catalog"."default" NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."api_key" OWNER TO "postgres";

-- ----------------------------
-- Table structure for banalyze
-- ----------------------------
DROP TABLE IF EXISTS "public"."banalyze";
CREATE TABLE "public"."banalyze" (
  "id" int4 NOT NULL DEFAULT nextval('banalyze_id_seq'::regclass),
  "key" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "description" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "value" text COLLATE "pg_catalog"."default" NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."banalyze" OWNER TO "postgres";

-- ----------------------------
-- Table structure for scan_domain
-- ----------------------------
DROP TABLE IF EXISTS "public"."scan_domain";
CREATE TABLE "public"."scan_domain" (
  "id" int4 NOT NULL DEFAULT nextval('scan_domain_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "domain" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "flag" bool,
  "nsq_flag" bool,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."scan_domain" OWNER TO "postgres";

-- ----------------------------
-- Table structure for scan_home
-- ----------------------------
DROP TABLE IF EXISTS "public"."scan_home";
CREATE TABLE "public"."scan_home" (
  "id" int4 NOT NULL DEFAULT nextval('scan_home_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "cus_remark" text COLLATE "pg_catalog"."default" NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."scan_home" OWNER TO "postgres";

-- ----------------------------
-- Table structure for scan_port
-- ----------------------------
DROP TABLE IF EXISTS "public"."scan_port";
CREATE TABLE "public"."scan_port" (
  "id" int4 NOT NULL DEFAULT nextval('scan_port_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "host" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "port" int4,
  "service_name" varchar(30) COLLATE "pg_catalog"."default",
  "vendor_product" varchar(200) COLLATE "pg_catalog"."default",
  "version" varchar(100) COLLATE "pg_catalog"."default",
  "flag" bool,
  "nsq_flag" bool,
  "http_flag" bool,
  "url" text COLLATE "pg_catalog"."default",
  "code" int4,
  "title" text COLLATE "pg_catalog"."default",
  "crack_flag" bool,
  "crack_nsq_flag" bool,
  "scan_flag" bool,
  "scan_nsq_flag" bool,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."scan_port" OWNER TO "postgres";

-- ----------------------------
-- Table structure for scan_subdomain
-- ----------------------------
DROP TABLE IF EXISTS "public"."scan_subdomain";
CREATE TABLE "public"."scan_subdomain" (
  "id" int4 NOT NULL DEFAULT nextval('scan_subdomain_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "domain" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "subdomain" varchar(500) COLLATE "pg_catalog"."default" NOT NULL,
  "ip" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "cname" varchar(200) COLLATE "pg_catalog"."default",
  "cdn" bool,
  "location" text COLLATE "pg_catalog"."default",
  "flag" bool,
  "nsq_flag" bool,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."scan_subdomain" OWNER TO "postgres";

-- ----------------------------
-- Table structure for scan_web
-- ----------------------------
DROP TABLE IF EXISTS "public"."scan_web";
CREATE TABLE "public"."scan_web" (
  "id" int4 NOT NULL DEFAULT nextval('scan_web_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "url" varchar(500) COLLATE "pg_catalog"."default" NOT NULL,
  "code" int4 NOT NULL,
  "title" varchar(500) COLLATE "pg_catalog"."default",
  "content_length" int4,
  "fingerprint" text COLLATE "pg_catalog"."default",
  "image" varchar(200) COLLATE "pg_catalog"."default",
  "screenshot_flag" bool,
  "js" text COLLATE "pg_catalog"."default",
  "urls" text COLLATE "pg_catalog"."default",
  "forms" text COLLATE "pg_catalog"."default",
  "secret" text COLLATE "pg_catalog"."default",
  "flag" bool,
  "nsq_flag" bool,
  "scan_flag" bool,
  "scan_nsq_flag" bool,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."scan_web" OWNER TO "postgres";

-- ----------------------------
-- Table structure for user_ip
-- ----------------------------
DROP TABLE IF EXISTS "public"."user_ip";
CREATE TABLE "public"."user_ip" (
  "id" int4 NOT NULL DEFAULT nextval('user_ip_id_seq'::regclass),
  "ip" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "lock" int4,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."user_ip" OWNER TO "postgres";

-- ----------------------------
-- Table structure for user_log
-- ----------------------------
DROP TABLE IF EXISTS "public"."user_log";
CREATE TABLE "public"."user_log" (
  "id" int4 NOT NULL DEFAULT nextval('user_log_id_seq'::regclass),
  "username" varchar(20) COLLATE "pg_catalog"."default" NOT NULL,
  "ip" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "user_agent" text COLLATE "pg_catalog"."default",
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."user_log" OWNER TO "postgres";

-- ----------------------------
-- Table structure for user_operation
-- ----------------------------
DROP TABLE IF EXISTS "public"."user_operation";
CREATE TABLE "public"."user_operation" (
  "id" int4 NOT NULL DEFAULT nextval('user_operation_id_seq'::regclass),
  "username" varchar(20) COLLATE "pg_catalog"."default" NOT NULL,
  "ip" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "theme" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "content" text COLLATE "pg_catalog"."default" NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."user_operation" OWNER TO "postgres";

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS "public"."users";
CREATE TABLE "public"."users" (
  "id" int4 NOT NULL DEFAULT nextval('users_id_seq'::regclass),
  "username" varchar(20) COLLATE "pg_catalog"."default" NOT NULL,
  "password" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "nick_name" varchar(100) COLLATE "pg_catalog"."default",
  "phone" varchar(20) COLLATE "pg_catalog"."default",
  "email" varchar(100) COLLATE "pg_catalog"."default",
  "remark" text COLLATE "pg_catalog"."default",
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."users" OWNER TO "postgres";

-- ----------------------------
-- Table structure for util_portscan_result
-- ----------------------------
DROP TABLE IF EXISTS "public"."util_portscan_result";
CREATE TABLE "public"."util_portscan_result" (
  "id" int4 NOT NULL DEFAULT nextval('util_portscan_result_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "host" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "port" int4,
  "service_name" varchar(30) COLLATE "pg_catalog"."default",
  "vendor_product" varchar(200) COLLATE "pg_catalog"."default",
  "version" varchar(100) COLLATE "pg_catalog"."default",
  "flag" bool,
  "nsq_flag" bool,
  "http_flag" bool,
  "url" varchar(500) COLLATE "pg_catalog"."default",
  "code" int4,
  "title" varchar(500) COLLATE "pg_catalog"."default",
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."util_portscan_result" OWNER TO "postgres";

-- ----------------------------
-- Table structure for util_portscan_task
-- ----------------------------
DROP TABLE IF EXISTS "public"."util_portscan_task";
CREATE TABLE "public"."util_portscan_task" (
  "id" int4 NOT NULL DEFAULT nextval('util_portscan_task_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "host_num" int4 NOT NULL,
  "scan_num" int4 NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."util_portscan_task" OWNER TO "postgres";

-- ----------------------------
-- Table structure for util_subdomain_result
-- ----------------------------
DROP TABLE IF EXISTS "public"."util_subdomain_result";
CREATE TABLE "public"."util_subdomain_result" (
  "id" int4 NOT NULL DEFAULT nextval('util_subdomain_result_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "domain" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "subdomain" varchar(500) COLLATE "pg_catalog"."default" NOT NULL,
  "ip" varchar(50) COLLATE "pg_catalog"."default" NOT NULL,
  "cname" text COLLATE "pg_catalog"."default",
  "cdn" bool,
  "location" text COLLATE "pg_catalog"."default",
  "flag" bool,
  "nsq_flag" bool,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."util_subdomain_result" OWNER TO "postgres";

-- ----------------------------
-- Table structure for util_subdomain_task
-- ----------------------------
DROP TABLE IF EXISTS "public"."util_subdomain_task";
CREATE TABLE "public"."util_subdomain_task" (
  "id" int4 NOT NULL DEFAULT nextval('util_subdomain_task_id_seq'::regclass),
  "cus_name" varchar(200) COLLATE "pg_catalog"."default" NOT NULL,
  "domain_num" int4 NOT NULL,
  "scan_num" int4 NOT NULL,
  "create_at" timestamp(6)
)
;
ALTER TABLE "public"."util_subdomain_task" OWNER TO "postgres";

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."api_key_id_seq"
OWNED BY "public"."api_key"."id";
SELECT setval('"public"."api_key_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."banalyze_id_seq"
OWNED BY "public"."banalyze"."id";
SELECT setval('"public"."banalyze_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."scan_domain_id_seq"
OWNED BY "public"."scan_domain"."id";
SELECT setval('"public"."scan_domain_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."scan_home_id_seq"
OWNED BY "public"."scan_home"."id";
SELECT setval('"public"."scan_home_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."scan_port_id_seq"
OWNED BY "public"."scan_port"."id";
SELECT setval('"public"."scan_port_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."scan_subdomain_id_seq"
OWNED BY "public"."scan_subdomain"."id";
SELECT setval('"public"."scan_subdomain_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."scan_web_id_seq"
OWNED BY "public"."scan_web"."id";
SELECT setval('"public"."scan_web_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."user_ip_id_seq"
OWNED BY "public"."user_ip"."id";
SELECT setval('"public"."user_ip_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."user_log_id_seq"
OWNED BY "public"."user_log"."id";
SELECT setval('"public"."user_log_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."user_operation_id_seq"
OWNED BY "public"."user_operation"."id";
SELECT setval('"public"."user_operation_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."users_id_seq"
OWNED BY "public"."users"."id";
SELECT setval('"public"."users_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."util_portscan_result_id_seq"
OWNED BY "public"."util_portscan_result"."id";
SELECT setval('"public"."util_portscan_result_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."util_portscan_task_id_seq"
OWNED BY "public"."util_portscan_task"."id";
SELECT setval('"public"."util_portscan_task_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."util_subdomain_result_id_seq"
OWNED BY "public"."util_subdomain_result"."id";
SELECT setval('"public"."util_subdomain_result_id_seq"', 2, false);

-- ----------------------------
-- Alter sequences owned by
-- ----------------------------
ALTER SEQUENCE "public"."util_subdomain_task_id_seq"
OWNED BY "public"."util_subdomain_task"."id";
SELECT setval('"public"."util_subdomain_task_id_seq"', 2, false);

-- ----------------------------
-- Uniques structure for table api_key
-- ----------------------------
ALTER TABLE "public"."api_key" ADD CONSTRAINT "api_key_key_key" UNIQUE ("key");

-- ----------------------------
-- Primary Key structure for table api_key
-- ----------------------------
ALTER TABLE "public"."api_key" ADD CONSTRAINT "api_key_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table banalyze
-- ----------------------------
ALTER TABLE "public"."banalyze" ADD CONSTRAINT "banalyze_key_key" UNIQUE ("key");

-- ----------------------------
-- Primary Key structure for table banalyze
-- ----------------------------
ALTER TABLE "public"."banalyze" ADD CONSTRAINT "banalyze_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table scan_domain
-- ----------------------------
ALTER TABLE "public"."scan_domain" ADD CONSTRAINT "scan_domain_domain_key" UNIQUE ("domain");

-- ----------------------------
-- Primary Key structure for table scan_domain
-- ----------------------------
ALTER TABLE "public"."scan_domain" ADD CONSTRAINT "scan_domain_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table scan_home
-- ----------------------------
ALTER TABLE "public"."scan_home" ADD CONSTRAINT "scan_home_cus_name_key" UNIQUE ("cus_name");

-- ----------------------------
-- Primary Key structure for table scan_home
-- ----------------------------
ALTER TABLE "public"."scan_home" ADD CONSTRAINT "scan_home_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Primary Key structure for table scan_port
-- ----------------------------
ALTER TABLE "public"."scan_port" ADD CONSTRAINT "scan_port_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table scan_subdomain
-- ----------------------------
ALTER TABLE "public"."scan_subdomain" ADD CONSTRAINT "scan_subdomain_subdomain_key" UNIQUE ("subdomain");

-- ----------------------------
-- Primary Key structure for table scan_subdomain
-- ----------------------------
ALTER TABLE "public"."scan_subdomain" ADD CONSTRAINT "scan_subdomain_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table scan_web
-- ----------------------------
ALTER TABLE "public"."scan_web" ADD CONSTRAINT "scan_web_url_key" UNIQUE ("url");

-- ----------------------------
-- Primary Key structure for table scan_web
-- ----------------------------
ALTER TABLE "public"."scan_web" ADD CONSTRAINT "scan_web_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table user_ip
-- ----------------------------
ALTER TABLE "public"."user_ip" ADD CONSTRAINT "user_ip_ip_key" UNIQUE ("ip");

-- ----------------------------
-- Primary Key structure for table user_ip
-- ----------------------------
ALTER TABLE "public"."user_ip" ADD CONSTRAINT "user_ip_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Primary Key structure for table user_log
-- ----------------------------
ALTER TABLE "public"."user_log" ADD CONSTRAINT "user_log_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Primary Key structure for table user_operation
-- ----------------------------
ALTER TABLE "public"."user_operation" ADD CONSTRAINT "user_operation_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table users
-- ----------------------------
ALTER TABLE "public"."users" ADD CONSTRAINT "users_username_key" UNIQUE ("username");

-- ----------------------------
-- Primary Key structure for table users
-- ----------------------------
ALTER TABLE "public"."users" ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Primary Key structure for table util_portscan_result
-- ----------------------------
ALTER TABLE "public"."util_portscan_result" ADD CONSTRAINT "util_portscan_result_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table util_portscan_task
-- ----------------------------
ALTER TABLE "public"."util_portscan_task" ADD CONSTRAINT "util_portscan_task_cus_name_key" UNIQUE ("cus_name");

-- ----------------------------
-- Primary Key structure for table util_portscan_task
-- ----------------------------
ALTER TABLE "public"."util_portscan_task" ADD CONSTRAINT "util_portscan_task_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Primary Key structure for table util_subdomain_result
-- ----------------------------
ALTER TABLE "public"."util_subdomain_result" ADD CONSTRAINT "util_subdomain_result_pkey" PRIMARY KEY ("id");

-- ----------------------------
-- Uniques structure for table util_subdomain_task
-- ----------------------------
ALTER TABLE "public"."util_subdomain_task" ADD CONSTRAINT "util_subdomain_task_cus_name_key" UNIQUE ("cus_name");

-- ----------------------------
-- Primary Key structure for table util_subdomain_task
-- ----------------------------
ALTER TABLE "public"."util_subdomain_task" ADD CONSTRAINT "util_subdomain_task_pkey" PRIMARY KEY ("id");
