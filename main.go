package main

import (
	"A-Secure-File-Sharing-System/client"
	"fmt"
)

// 这里要写一个shell的界面以方便用户交互
func main() {
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
