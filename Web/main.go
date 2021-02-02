package main

import (
	_ "Web/boot"
	_ "Web/router"

	"github.com/gogf/gf/frame/g"
)

func main() {
	g.Server().Run()
}