package main

import (
	"A-Secure-File-Sharing-System/client"
	"errors"
	"io"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

const preferenceCurrentTutorial = "currentTutorial"

var topWindow fyne.Window

// 登陆界面
func makeLogin_returnWindow() (fyne.Window, error) {
	app := fyne.CurrentApp()
	// 登陆窗口
	loginWidget := app.NewWindow("LogIn")

	username := widget.NewEntry()
	username.SetPlaceHolder("John Smith")

	// email := widget.NewEntry()
	// email.SetPlaceHolder("test@example.com")
	// email.Validator = validation.NewRegexp(`\w{1,}@\w{1,}\.\w{1,4}`, "not a valid email")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Name", Widget: username, HintText: "Your username"},
			{Text: "Password", Widget: password, HintText: "Your passwrod"},
		},
		OnCancel: func() {
			loginWidget.Close()
			log.Println("quit")
		},
		OnSubmit: func() {
			if authenticate(username.Text, password.Text) {

				User, _ := client.GetUser(username.Text, password.Text)
				showMainWindow(app, User)
				loginWidget.Close()
				// // 发送显示主界面的操作到主 goroutine 中
				// app.Send(func() {
				// 	showMainWindow(fyneApp)
				// })
			} else {
				dialog.ShowError(errors.New("invalid username or password"), loginWidget)
			}
		},
	}

	// 注册按钮
	registerButton := makeRegisterButton(loginWidget)

	container := container.New(layout.NewVBoxLayout(), form, registerButton)

	loginWidget.SetContent(container)
	// loginWidget.SetContent(content)
	loginWidget.Resize(fyne.NewSize(340, 460))
	loginWidget.Show()
	return loginWidget, nil

}

func makeLogin() error {
	_, err := makeLogin_returnWindow()
	return err
}

// func makeLogin_v2(app fyne.App) error {
// 	// 登陆窗口
// 	loginWidget := app.NewWindow("LogIn")
// 	// 创建登录界面的代码
// 	// 包括用户名、密码输入框、登录按钮等
// 	username := widget.NewEntry()
// 	username.SetPlaceHolder("John Smith")
// 	password := widget.NewPasswordEntry()
// 	password.SetPlaceHolder("Password")
// 	loginButton := widget.NewButton("click me", func() {
// 		if authenticate(username.Text, password.Text) {
// 			loginWidget.Close()
// 			showMainWindow(app,)
// 		} else {
// 			dialog.ShowError(errors.New("invalid username or password"), loginWidget)
// 		}
// 	})

// 	content := container.New(layout.NewVBoxLayout(), username, password, layout.NewSpacer(), loginButton)
// 	loginWidget.SetContent(container.New(layout.NewVBoxLayout(), content))
// 	// loginWidget.SetContent(content)
// 	loginWidget.Resize(fyne.NewSize(340, 460))
// 	loginWidget.Show()
// 	return nil
// }

// 注册界面
func makeRegisterButton(win fyne.Window) *widget.Button {
	registerButton := widget.NewButton("Register", func() {
		// 关闭当前登陆界面，加载注册界面
		showRegisterWindow()
		win.Close()
	})

	return registerButton
}

func showRegisterWindow() {
	app := fyne.CurrentApp()
	// 登陆窗口
	registerWidget := app.NewWindow("Register")

	username := widget.NewEntry()
	username.SetPlaceHolder("John Smith")

	// email := widget.NewEntry()
	// email.SetPlaceHolder("test@example.com")
	// email.Validator = validation.NewRegexp(`\w{1,}@\w{1,}\.\w{1,4}`, "not a valid email")

	password1 := widget.NewPasswordEntry()
	password1.SetPlaceHolder("Password")
	password2 := widget.NewPasswordEntry()
	password2.SetPlaceHolder("Password")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Name", Widget: username, HintText: "Your username"},
			{Text: "Password", Widget: password1, HintText: "Your passwrod"},
			{Text: "Password", Widget: password2, HintText: "Conform your passwrod"},
		},
		OnCancel: func() {
			defer registerWidget.Close()
			// 跳回登陆界面
			err := makeLogin()
			if err != nil {
				log.Fatal(err)
			}
			log.Println("register -> login")
		},
		OnSubmit: func() {
			err := authenticate_register(username.Text, password1.Text, password2.Text)
			if err != nil {
				dialog.ShowError(err, registerWidget)
			} else {
				defer registerWidget.Close()
				// 跳回登陆界面
				win, err := makeLogin_returnWindow()
				if err != nil {
					log.Fatal(err)
				}
				dialog.ShowInformation("Success", "Registered successfully!", win)
				log.Println("register -> login")
			}
		},
	}

	// 注册按钮

	registerWidget.SetContent(form)
	// loginWidget.SetContent(content)
	registerWidget.Resize(fyne.NewSize(340, 460))
	registerWidget.Show()

}

func authenticate(username, password string) bool {
	// 用户认证的逻辑
	// 这里可以是用户名密码验证、API 调用等
	_, err := client.GetUser(username, password)
	if err != nil {
		log.Println(err.Error())
		return false
	}
	return true
}

// 用户注册验证
func authenticate_register(username, password1, password2 string) error {
	if password1 != password2 {
		log.Println("password1 != password2")
		return errors.New("password1 != password2")
	}
	// username 好像需要唯一

	_, err := client.InitUser(username, password1)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	return nil
}

func showMainWindow(app fyne.App, User *client.User) {

	log.Println("登陆成功")

	w := app.NewWindow("test")

	w.Resize(fyne.NewSize(640, 460)) // 重置窗口大小

	// newNav := makeNav()
	// w.SetContent(newNav)

	newTabs := makeTabs(w, User)
	w.SetContent(newTabs)

	w.Show()
	// log.Println("w.Show()")

}

func makeTabs(win fyne.Window, User *client.User) fyne.CanvasObject {

	// StoreFileButtion := makeDialogOpenFileButton(win)
	StoreFile := makeStoreFile(win, User)
	LoadFile := makeLoadFile(win, User)
	tabs := container.NewAppTabs(
		container.NewTabItem("StoreFile", StoreFile),
		container.NewTabItem("LoadFile", LoadFile),
		container.NewTabItem("AppendToFile", widget.NewLabel("AppendToFile")),
		container.NewTabItem("CreateInvitation", widget.NewLabel("CreateInvitation")),
		container.NewTabItem("AcceptInvitation", widget.NewLabel("AcceptInvitation")),
		container.NewTabItem("RevokeAccess", widget.NewLabel("RevokeAccess")),
	)

	//tabs.Append(container.NewTabItemWithIcon("Home", theme.HomeIcon(), widget.NewLabel("Home tab")))

	tabs.SetTabLocation(container.TabLocationLeading)

	return tabs
}

func makeDialogOpenFileButton(win fyne.Window, filename *string, data *[]byte) *widget.Button {
	openFile := widget.NewButton("File Open Without Filter", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			if reader == nil {
				log.Println("Cancelled")
				return
			}

			// imageOpened(reader)
			*filename = reader.URI().Name()
			*data, err = io.ReadAll(reader)
			if err != nil {
				fyne.LogError("Failed to load file data", err)
				return
			}
			log.Printf("the filename: %s, the file content: %s", *filename, string(*data))
		}, win)
		// fd.SetFilter(storage.NewExtensionFileFilter([]string{".png", ".jpg", ".jpeg"}))
		fd.Show()
	})

	return openFile
}

func makeDialogFileSaveButton(win fyne.Window, filename *string, User *client.User) *widget.Button {
	saveFile := widget.NewButton("File Save", func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			if writer == nil {
				log.Println("Cancelled")
				return
			}
			fileSaved(writer, win, filename, User)

		}, win)
	})

	return saveFile
}

func fileSaved(f fyne.URIWriteCloser, w fyne.Window, filename *string, User *client.User) {
	defer f.Close()

	// loadFile
	if len(*filename) == 0 {
		err := errors.New("filename is empty")
		dialog.ShowError(err, w)
		return
	}
	log.Printf("filename: %s", *filename)
	data, err := User.LoadFile(*filename)
	if err != nil {
		log.Println(err.Error())
		dialog.ShowError(err, w)
		return
	}
	log.Printf("data: %s", data)
	_, err = f.Write(data)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	dialog.ShowInformation("Success", "The file was successfully saved locally.", w)
	log.Println("Saved to...", f.URI())
}

func makeStoreFile(win fyne.Window, User *client.User) fyne.CanvasObject {
	// layout
	// 打开文件按钮
	// 保存上传按钮

	var filename string
	var data []byte

	StoreFileButtion := makeDialogOpenFileButton(win, &filename, &data)

	StoreAndUploadButton := widget.NewButton("upload", func() {
		if len(filename) == 0 || len(data) == 0 {
			log.Println("File does not exist.")
			dialog.ShowInformation("Error", "File does not exist!", win)
			// dialog.NewError(errors.New("file does not exist"), win)
			return
		}
		err := User.StoreFile(filename, data)
		if err != nil {
			fyne.LogError("failed to storefile", err)
			return
		}
		dialog.ShowInformation("Success", "File uploaded successfully.", win)
		filename = ""
		data = nil
		log.Println("test ShowInformation")
	})

	content := container.New(layout.NewVBoxLayout(), StoreFileButtion, layout.NewSpacer(), StoreAndUploadButton)
	return content
}

func makeLoadFile(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 输入文件名的输入框
	filename := widget.NewEntry()
	filename.SetPlaceHolder("Enter the filename")

	// 保存按钮
	LoadAndSaveButton := makeDialogFileSaveButton(win, &filename.Text, User)

	// 从datastore获取数据
	// 保存到本地文件夹

	content := container.New(layout.NewVBoxLayout(), filename, layout.NewSpacer(), LoadAndSaveButton)

	return content

}
