FROM alpine

WORKDIR /goscan
COPY . .
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && apk update && apk add ca-certificates && rm -rf /var/cache/apk/* && chmod +x Client
CMD ["./Client"]

# docker build -t goscan:v1 .
# docker run -itd --name scan1 goscan:v1

# ./nsqd -tcp-address 192.168.31.157:4150 -http-address 192.168.31.157:4151 -max-msg-timeout 1h