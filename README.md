# An-End-to-End-Encrypted-File-Sharing-System
An End-to-End Encrypted File Sharing System

项目目录结构

```
├── LICENSE							证书
├── README.md						说明书
├── client
│   ├── client.go					用户部分
│   ├── client_unittest.go			 用户单元测试	
│   └── utils.go					工具函数
├── client_test	
│   └── client_test.go				 测试
├── fyne-cross                      编译后的可执行程序
├── userlib_client                  修改后的客户端库函数
├── design.md						设计文档
├── design.pdf						设计文档
├── go.mod						
├── go.sum
└── main.go							主代码

```

## How to compile and package across platforms
### 参考：    
- https://github.com/fyne-io/fyne-cross 
- https://docs.fyne.io/started/cross-compiling	
### Requirements
- go >= 1.14
- docker
### Installation
For go >= 1.16:
`go install github.com/fyne-io/fyne-cross@latest`
### Build
- Windows: `fyne-cross windows -arch=* -app-id="A-Secure-File-Sharing-System.MyApp"` 
- Linux: `fyne-cross linux`



## To do list

- [x] main.go修改
- [x] gui
- [x] 打包exe
- [x] User部分的函数
- [x] File相关的函数
- [x] Invitation相关的函数



