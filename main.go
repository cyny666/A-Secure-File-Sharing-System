package main

import (
	"A-Secure-File-Sharing-System/client"
	"fmt"
	"log"

	"fyne.io/fyne/v2/app"
)

func main() {
	// 初始化测试用户
	client.InitUser("test", "test")

	// 创建应用程序
	fyneApp := app.NewWithID("test")

	// 创建登录界面
	err := makeLogin()
	if err != nil {
		log.Fatal(err)
	}

	// 运行应用程序
	fyneApp.Run()
}

// 这里要写一个shell的界面以方便用户交互
func main_v1() {
	user1, erro := client.InitUser("cyny666", "123456")
	if erro != nil {
		fmt.Print(erro)
	}
	user2, erro2 := client.GetUser("cyny666", "123456")
	if erro2 != nil {
		fmt.Println(erro2)
	}
	fmt.Print(user1)
	fmt.Println(user2)
}
