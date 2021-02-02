package model

// 框架模块路由所需信息
type FrameRoute struct{
	HomeInfo ModuleRoute `json:"homeInfo"`
	LogoInfo ModuleRoute `json:"logoInfo"`
	MenuInfo []SonModuleRoute `json:"menuInfo"`
}

// 主框架描述信息
type ModuleRoute struct{
	Title string `json:"title"`
	Image string `json:"image"`
	Href string `json:"href"`
}

// 主框架模块路由
type SonModuleRoute struct{
	Title string `json:"title"`
	Icon string `json:"icon"`
	Href string `json:"href"`
	Target string `json:"target"`
	Child []SonModuleRoute `json:"child"`
}

// ModuleInit 生成模块路由
func ModuleInit()FrameRoute{
	frameRoute := FrameRoute{}
	frameRoute.HomeInfo = ModuleRoute{
		Title: "首页",
	}
	frameRoute.LogoInfo = ModuleRoute{
		Title:"GoScan",
		Image:"/images/logo.png",
	}
	frameRoute.MenuInfo = []SonModuleRoute{
		scanMenu(),
		utilMenu(),
		userMenu(),

	}
	return frameRoute
}

// user菜单
func userMenu()SonModuleRoute{
	return SonModuleRoute{
		Title:"后台管理",
		Icon:"fa fa-cog",
		Target:"_self",
		Child:[]SonModuleRoute{
			SonModuleRoute{
				Title:"用户管理",
				Icon:"fa fa-users",
				Target:"_self",
				Child:[]SonModuleRoute{
					SonModuleRoute{
						Title:"用户管理",
						Icon:"fa fa-user",
						Target:"_self",
						Href: "user/manager",
					},
					SonModuleRoute{
						Title:"IP锁定管理",
						Icon:"fa fa-unlock-alt",
						Target:"_self",
						Href: "user/userip",
					},
				},
			},
			SonModuleRoute{
				Title:"日志管理",
				Icon:"fa fa-book",
				Target:"_self",
				Child:[]SonModuleRoute{
					SonModuleRoute{
						Title:"登录日志",
						Icon:"fa fa-calendar",
						Target:"_self",
						Href: "user/loginlog",
					},
					SonModuleRoute{
						Title:"操作日志",
						Icon:"fa fa-calendar-o",
						Target:"_self",
						Href: "user/operation",
					},
				},
			},
			SonModuleRoute{
				Title:"消息通知管理",
				Icon:"fa fa-bell-o",
				Target:"_self",
				Child:[]SonModuleRoute{
					SonModuleRoute{
						Title:"SMTP配置",
						Icon:"fa fa-envelope-o",
						Target:"_self",
						Href: "user/smtp",
					},
					SonModuleRoute{
						Title:"Server酱配置",
						Icon:"fa fa-bell",
						Target:"_self",
						Href: "user/ftqq",
					},
				},
			},
		},
	}
}

// util实用程序菜单
func utilMenu()SonModuleRoute{
	return SonModuleRoute{
		Title:"实用工具",
		Icon:"fa fa-anchor",
		Target:"_self",
		Child:[]SonModuleRoute{
			SonModuleRoute{
				Title:"提权辅助",
				Icon:"fa fa-user-secret",
				Target:"_self",
				Child:[]SonModuleRoute{
					SonModuleRoute{
						Title:"杀软检测",
						Icon:"fa fa-bug",
						Target:"_self",
						Href: "util/avcheck",
					},
				},
			},
			SonModuleRoute{
				Title:"信息收集",
				Icon:"fa fa-eye",
				Target:"_self",
				Child:[]SonModuleRoute{
					SonModuleRoute{
						Title:"Web指纹识别",
						Icon:"fa fa-binoculars",
						Target:"_self",
						Href: "util/banalyze/scan",
					},
					SonModuleRoute{
						Title:"子域名扫描",
						Icon:"fa fa-bullseye",
						Target:"_self",
						Href: "util/subdomain/manager",
					},
					SonModuleRoute{
						Title:"端口扫描",
						Icon:"fa fa-eye",
						Target:"_self",
						Href: "util/portscan/manager",
					},
				},
			},
			SonModuleRoute{
				Title:"Web指纹库",
				Icon:"fa fa-leaf",
				Target:"_self",
				Href: "util/banalyze",
			},
		},
	}
}

// 综合扫描菜单
func scanMenu()SonModuleRoute{
	return SonModuleRoute{
		Title:"综合扫描",
		Icon:"fa fa-crosshairs",
		Target:"_self",
		Child:[]SonModuleRoute{
			SonModuleRoute{
				Title:"厂商管理",
				Icon:"fa fa-codepen",
				Target:"_self",
				Href: "scan/manager",
			},
			SonModuleRoute{
				Title:"子域名",
				Icon:"fa fa-bullseye",
				Target:"_self",
				Href: "scan/subdomain",
			},
			SonModuleRoute{
				Title:"端口",
				Icon:"fa fa-eye",
				Target:"_self",
				Href: "scan/portscan",
			},
			SonModuleRoute{
				Title:"扫描引擎",
				Icon:"fa fa-steam",
				Target:"_self",
				Href: "scan/engine",
			},
		},
	}
}