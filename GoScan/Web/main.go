package main

import (
	_ "github.com/CTF-MissFeng/GoScan/Web/boot"
	_ "github.com/CTF-MissFeng/GoScan/Web/router"

	"github.com/gogf/gf/frame/g"
)

func main() {
	g.Server().Run()
}
