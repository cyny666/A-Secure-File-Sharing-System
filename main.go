package main

import (
	"A-Secure-File-Sharing-System/client"
	"log"
	"os"

	"fyne.io/fyne/v2/app"
)

func main() {

	inits()
	// 初始化测试用户
	_, err := client.InitUser("test", "test")
	if err != nil {
		log.Printf("err initUser: %s\n", err.Error())
	}

	// 创建应用程序
	fyneApp := app.NewWithID("A-Secure-File-Sharing-System")

	// 创建登录界面
	err = makeLogin()
	if err != nil {
		log.Fatal(err)
	}

	// 运行应用程序
	fyneApp.Run()

	// 取消环境变量
	os.Unsetenv("FYNE_FONT")
}
