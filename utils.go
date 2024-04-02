package main

import (
	"A-Secure-File-Sharing-System/client"
	"errors"
	"fmt"
	"io"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/google/uuid"
)

// 登陆界面（返回所创建的Window)
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

// 登陆界面（不返回所创建的Window)
func makeLogin() error {
	_, err := makeLogin_returnWindow()
	return err
}

// 注册按钮
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

	w.Resize(fyne.NewSize(600, 350)) // 重置窗口大小

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
	AppendToFile := makeAppendToFile(win, User)
	CreateInvitaion := makeCreateInvitation(win, User)
	AcceptInvitation := makeAcceptInvitation(win, User)
	revokeAccess := makeRevokeAccess(win, User)
	tabs := container.NewAppTabs(
		container.NewTabItem("StoreFile", StoreFile),
		container.NewTabItem("LoadFile", LoadFile),
		container.NewTabItem("AppendToFile", AppendToFile),
		container.NewTabItem("CreateInvitation", CreateInvitaion),
		container.NewTabItem("AcceptInvitation", AcceptInvitation),
		container.NewTabItem("RevokeAccess", revokeAccess),
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

// func makeDialogFileSaveButton(win fyne.Window, filename *string, User *client.User) *widget.Button {
// 	saveFile := widget.NewButton("File Save", func() {
// 		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
// 			if err != nil {
// 				dialog.ShowError(err, win)
// 				return
// 			}
// 			if writer == nil {
// 				log.Println("Cancelled")
// 				return
// 			}
// 			fileSaved(writer, win, filename, User)

// 		}, win)
// 	})

// 	return saveFile
// }

func loadFile(win fyne.Window, filename string, User *client.User) {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, win)
			return
		}
		if writer == nil {
			log.Println("Cancelled")
			return
		}
		err2 := fileSaved(writer, filename, User)
		if err2 != nil {
			dialog.ShowError(err2, win)
			return
		} else {
			dialog.ShowInformation("Success", "The file was successfully saved locally.", win)
			log.Println("Saved to...", writer.URI())
			return
		}

	}, win)
}

func fileSaved(f fyne.URIWriteCloser, filename string, User *client.User) error {
	defer f.Close()

	// loadFile
	if len(filename) == 0 {
		err := errors.New("filename is empty")
		return err
	}
	log.Printf("filename: %s", filename)
	data, err := User.LoadFile(filename)
	if err != nil {
		return err
	}
	log.Printf("data: %s", data)
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	// dialog.ShowInformation("Success", "The file was successfully saved locally.", w)
	log.Println("Saved to...", f.URI())

	return nil
}

func makeStoreFile(win fyne.Window, User *client.User) fyne.CanvasObject {
	// layout
	// 打开文件按钮
	// 保存上传按钮

	var filename string
	var data []byte

	StoreFileButtion := makeDialogOpenFileButton(win, &filename, &data)

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Select local file: ", Widget: StoreFileButtion},
		},
		OnCancel: func() {
			log.Println("Cancelled")
			filename = ""
			data = nil
		},
		OnSubmit: func() {
			err := storeFile(filename, data, User)
			if err != nil {
				dialog.ShowError(err, win)
			} else {
				dialog.ShowInformation("Success", "File uploaded successfully.", win)
				filename = ""
				data = nil
				log.Println("File uploaded successfully")
			}
		},
	}
	// StoreAndUploadButton := widget.NewButton("upload", func() {
	// 	if len(filename) == 0 || len(data) == 0 {
	// 		log.Println("File does not exist.")
	// 		dialog.ShowInformation("Error", "File does not exist!", win)
	// 		// dialog.NewError(errors.New("file does not exist"), win)
	// 		return
	// 	}
	// 	err := User.StoreFile(filename, data)
	// 	if err != nil {
	// 		fyne.LogError("failed to storefile", err)
	// 		return
	// 	}
	// 	dialog.ShowInformation("Success", "File uploaded successfully.", win)
	// 	filename = ""
	// 	data = nil
	// 	log.Println("test ShowInformation")
	// })
	// content := container.New(layout.NewVBoxLayout(), StoreFileButtion, layout.NewSpacer(), StoreAndUploadButton)
	return form
}

func makeLoadFile(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 输入文件名的输入框
	filename := widget.NewEntry()
	filename.SetPlaceHolder("xxx.txt")

	// 保存按钮
	// LoadAndSaveButton := makeDialogFileSaveButton(win, &filename.Text, User)

	form := &widget.Form{
		SubmitText: "File Save",
		Items: []*widget.FormItem{
			{Text: "Filename: ", Widget: filename, HintText: "Input the filename to load"},
		},
		OnCancel: func() {
			log.Println("Cancelled")
			filename.SetText("")
		},
		OnSubmit: func() {
			loadFile(win, filename.Text, User)
			filename.SetText("")
		},
	}

	return form

}

func makeAppendToFile(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 输入文件名
	// 输入内容
	// 确认

	filename := widget.NewEntry()
	filename.SetPlaceHolder("xxx.txt")

	appendText := widget.NewMultiLineEntry()

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Filename", Widget: filename, HintText: "Input the filename"},
			{Text: "Content to add", Widget: appendText},
		},
		OnCancel: func() {
			fmt.Println("Cancelled")
			appendText.SetText("") // 清空输入文本

		},
		OnSubmit: func() {
			fmt.Println("Form submitted")
			err := appendToFile(filename.Text, appendText.Text, User)
			if err != nil {
				dialog.ShowError(err, win)
			} else {
				dialog.ShowInformation("Success", "Successfully added content!", win)
				appendText.SetText("") // 清空输入文本
			}

		},
	}
	// form.Append("Password", password)
	// form.Append("Disabled", disabled)
	// form.Append("Message", largeText)
	return form
}

func makeCreateInvitation(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 输入文件名
	// 输入邀请用户的名称

	filename := widget.NewEntry()
	filename.SetPlaceHolder("xxx.txt")

	username := widget.NewEntry()
	username.SetPlaceHolder("John Smith")

	form := &widget.Form{
		SubmitText: "Confirm",
		Items: []*widget.FormItem{
			{Text: "Filename: ", Widget: filename, HintText: "Input the filename to share"},
			{Text: "Username: ", Widget: username, HintText: "Input the user to invite"},
		},
		OnCancel: func() {
			log.Println("Cancelled")
			filename.SetText("")
			username.SetText("")
		},
		OnSubmit: func() {
			invitationUUID, err := createInvitation(filename.Text, username.Text, User)
			if err != nil {
				dialog.ShowError(err, win)
			} else {
				message := "Successfully generate the invitation UUID: \n" + invitationUUID.String()
				dialog.ShowInformation("Success", message, win)
			}
			filename.SetText("")
			username.SetText("")
		},
	}

	return form
}

func makeAcceptInvitation(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 邀请者的用户名
	// 邀请UUID
	// 文件名
	senderUsername := widget.NewEntry()
	senderUsername.SetPlaceHolder("John Smith")

	invitationUUID_btn := widget.NewEntry()
	invitationUUID_btn.SetPlaceHolder("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

	filename := widget.NewEntry()
	filename.SetPlaceHolder("xxx.txt")

	form := &widget.Form{
		SubmitText: "Confirm",
		Items: []*widget.FormItem{
			{Text: "Username: ", Widget: senderUsername, HintText: "Input the username of Inviter"},
			{Text: "InvitationUUID: ", Widget: invitationUUID_btn, HintText: "Input the Invitation UUID"},
			{Text: "Filename: ", Widget: filename, HintText: "Input the shared filename"},
		},
		OnCancel: func() {
			log.Println("Cancelled")
			senderUsername.SetText("")
			invitationUUID_btn.SetText("")
			filename.SetText("")
		},
		OnSubmit: func() {
			err := acceptInvitation(senderUsername.Text, invitationUUID_btn.Text, filename.Text, User)
			if err != nil {
				dialog.ShowError(err, win)
			} else {
				dialog.ShowInformation("Success", "Successfully accept the invitation!", win)
			}
			senderUsername.SetText("")
			invitationUUID_btn.SetText("")
			filename.SetText("")
		},
	}

	return form
}

func makeRevokeAccess(win fyne.Window, User *client.User) fyne.CanvasObject {
	// 文件名
	// 接收邀请的用户名
	filename := widget.NewEntry()
	filename.SetPlaceHolder("xxx.txt")

	recipientUsername := widget.NewEntry()
	recipientUsername.SetPlaceHolder("John Smith")

	form := &widget.Form{
		SubmitText: "Confirm",
		Items: []*widget.FormItem{
			{Text: "Filename: ", Widget: filename, HintText: "Input the filename to revoke"},
			{Text: "Username: ", Widget: recipientUsername, HintText: "Input the targer user's name"},
		},
		OnCancel: func() {
			log.Println("Cancelled")
			filename.SetText("")
			recipientUsername.SetText("")
		},
		OnSubmit: func() {
			err := revokeAccess(filename.Text, recipientUsername.Text, User)
			if err != nil {
				dialog.ShowError(err, win)
			} else {
				dialog.ShowInformation("Success", "Successfully revoke the target user's access to specified file!", win)
			}
			filename.SetText("")
			recipientUsername.SetText("")
		},
	}

	return form
}

func storeFile(filename string, data []byte, User *client.User) error {
	if len(filename) == 0 {
		err := errors.New("filename is empty")
		log.Println(err.Error())
		return err
	}
	err := User.StoreFile(filename, data)
	if err != nil {
		fyne.LogError("failed to storefile", err)
		return err
	}
	return nil
}

func appendToFile(filename string, appendText string, User *client.User) error {
	appendBytes := []byte(appendText)
	err := User.AppendToFile(filename, appendBytes)
	return err
}

func createInvitation(filename string, username string, User *client.User) (invitationPtr uuid.UUID, err error) {
	if len(filename) == 0 {
		return uuid.Nil, errors.New("filename is empty")
	}
	if len(username) == 0 {
		return uuid.Nil, errors.New("target username is empty")
	}
	invitationPtr, err = User.CreateInvitation(filename, username)
	return
}

func acceptInvitation(senderUsername string, invitationUUID_str string, filename string, User *client.User) error {
	invitationUUID, err := uuid.Parse(invitationUUID_str)
	if err != nil {
		return err
	}
	err = User.AcceptInvitation(senderUsername, invitationUUID, filename)
	return err

}

func revokeAccess(filename string, recipientUsername string, User *client.User) error {
	if len(filename) == 0 {
		return errors.New("filename is empty")
	}
	if len(recipientUsername) == 0 {
		return errors.New("username is empty")
	}
	err := User.RevokeAccess(filename, recipientUsername)
	return err
}
