package main

import (
	"A-Secure-File-Sharing-System/client"
	"fmt"
)

//func main() {
//	// 初始化测试用户
//	client.InitUser("test", "test")
//
//	// 创建应用程序
//	fyneApp := app.NewWithID("test")
//
//	// 创建登录界面
//	err := makeLogin()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// 运行应用程序
//	fyneApp.Run()
//}

// 这里要写一个shell的界面以方便用户交互
func main() {
	// 初始化用户
	user1, err := client.InitUser("cyny666", "123456")
	if err != nil {
		fmt.Print(err)
		return
	}

	// 调用 StoreFile 函数
	err = user1.StoreFile("example.txt", []byte("Hello, world!"))
	if err != nil {
		fmt.Print(err)
	}
	content, _ := user1.LoadFile("example.txt")
	fmt.Print(string(content))
}
