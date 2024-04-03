package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
// 这里来定义一下结构体
type TreeNode struct {
	Value    uuid.UUID
	Children []*TreeNode
	Friend   []uuid.UUID
	Father   *TreeNode
}
type User struct {
	Username string
	Password string
	// Private_key是用来对用户进行解密的
	// Signature_key是用来对数据进行解密的
	Private_key   userlib.PKEDecKey
	Signature_key userlib.DSSignKey
	// 这里对于Intermediate Id想以树的方式来定义
	IntermediateUUIDmap TreeNode
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type FileNode struct {
	// 定义一下前面的UUID和后面的UUID（有点像队列）
	UUID     uuid.UUID
	PrevUUID uuid.UUID
	NextUUID uuid.UUID
	Content  []byte
}

// 包含文件对应的 FileNode 地址
type FileLocator struct {
	FileNodeUUIDs []uuid.UUID
	SymKeyFn      []byte
}

// 每个用户通过 keyFile 来打开 file
type KeyFile struct {
	isFileOwner bool
	FileUUID    uuid.UUID
	SymKeyFile  []byte
	MacKeyFile  []byte
}

// 文件分享结构体，键值为filename+文件拥有者UUID,为了与文件存贮位置区分开
type Invitationfile struct {
	InvitationID   uuid.UUID //分享验证码
	InvitationTree *TreeNode
	SymKeyFile     []byte
	MacKeyFile     []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//如果名字为空
	if len(username) == 0 {
		return nil, errors.New("输入的名字必须不为空")
	}
	// 对username进行一个SHA-512加密获取其哈希值
	hashUsername := userlib.Hash([]byte(username))
	// 选取前十六位作为UUID
	userUUID, err := uuid.FromBytes(hashUsername[:16])
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// 限制username没有重名
	if _, ok := userlib.DatastoreGet(userUUID); ok == true {
		return nil, errors.New("您选取的username有重复的")
	}
	// 创建公/私钥和签名
	// 这里的公私钥可以用来解密Invitation
	publicKey, privatekey, _ := userlib.PKEKeyGen()
	signatureKey, verifyKey, _ := userlib.DSKeyGen()
	// 将公私钥和签名传到KeyStore中
	err = userlib.KeystoreSet(username+"publicKey", publicKey)
	if err != nil {
		return nil, errors.New("生成的公钥不可以储存到Keystore上")
	}
	err = userlib.KeystoreSet(username+"verfyKey", verifyKey)
	if err != nil {
		return nil, errors.New("签名公钥不可以储存到Ketstore上")
	}
	// 创建一个新User
	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.Private_key = privatekey
	userdata.Signature_key = signatureKey
	userdataBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("无法把用户转为byte流")
	}
	hmacTag, newUserEncrypted, err := userdata.GenerateHmacTag(userdataBytes)
	if err != nil {
		return nil, errors.New("消息认证码不对")
	}
	userlib.DatastoreSet(userUUID, append(newUserEncrypted, hmacTag...))
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// 对username进行一个SHA-512加密获取其哈希值
	hashUsername := userlib.Hash([]byte(username))
	// 选取前十六位作为UUID
	userUUID, err := uuid.FromBytes(hashUsername[:16])
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// 查找Datastore中是否存储有该userUUID
	if _, ok := userlib.DatastoreGet(userUUID); ok == false {
		return nil, errors.New("您选取的username不存在")
	}
	// 获取Datastore中存储的加密的数据
	data, ok := userlib.DatastoreGet(userUUID)
	if ok != true {
		return nil, errors.New("找不到Datastore中的数据")
	}
	// 分理出newUserEncryted 和hamcTag
	newUserEncryted := data[:len(data)-64]
	hmacTag := data[len(data)-64:]
	// 来验证hmacTag是否一样
	// 生成堆成加密密钥和消息认证密码
	symEncKey, macKey := GenerateKeys(username, password)
	hmacTagVerify, hmacError := userlib.HMACEval(macKey, newUserEncryted)
	if hmacError != nil {
		return nil, errors.New("输入的秘钥应为16byte")
	}
	// 判断password是否正确
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return nil, errors.New("数据被修改或者密码错误")
	}
	//解密数据
	UserBytes_jsoned := userlib.SymDec(symEncKey, newUserEncryted)

	err_Marshal := json.Unmarshal(UserBytes_jsoned, &userdata)
	if err_Marshal != nil {
		return nil, err_Marshal
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//定义一个FileLocator
	var filelocator FileLocator
	var filenode FileNode
	// 生成filenode的UUID
	filenode.UUID = uuid.New()
	filenode.Content = content
	// 生成filelocator的ID
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	filelocator.FileNodeUUIDs = append(filelocator.FileNodeUUIDs, filenode.UUID)
	// 把文件存入filenode中
	if err != nil {
		return err
	}
	// 将content json序列化
	contentBytes, err := json.Marshal(filelocator)
	if err != nil {
		return err
	}
	filenode_content, err := json.Marshal(filenode)
	if err != nil {
		return err
	}
	hmacTag_filenode, newUserEncrypted, err := userdata.GenerateHmacTag(filenode_content)
	if err != nil {
		return err
	}
	// 把filenode的content存储到filenode的UUID上
	userlib.DatastoreSet(filenode.UUID, append(newUserEncrypted, hmacTag_filenode...))
	PublicKey, ok := userlib.KeystoreGet(userdata.Username + "publicKey")
	if ok != true {
		return errors.New("用户的公钥丢失了")
	}
	// 对locator_ciphertext用RSA进行加密
	ciphertext, err := userlib.PKEEnc(PublicKey, contentBytes)
	hmacTag, newUserEncrypted_filelocator, err := userdata.GenerateHmacTag(ciphertext)
	if err != nil {
		return err
	}
	// 查找Datastore中是否存储有该userUUID
	if _, ok := userlib.DatastoreGet(storageKey); ok == true {
		return errors.New("您已经储存过该文件")
	}
	// 将哈希消息认证码和LocatorContent存储到这里
	newUserEncrypted_filelocator = append(newUserEncrypted_filelocator, hmacTag...)
	userlib.DatastoreSet(storageKey, newUserEncrypted_filelocator)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// 定义一个filenode来储存append的文件
	var filelocator FileLocator
	var filenode FileNode
	filelocator, err := userdata.DecryptFilelocator(filename)
	if err != nil {
		return err
	}
	// 生成一个新的filenodeUUID
	filenode.UUID = uuid.New()
	filelocator.FileNodeUUIDs = append(filelocator.FileNodeUUIDs, filenode.UUID)
	// 将filelocator重新存储到数据库
	userdata.StoreFilelocator(filelocator, filename)
	filenode.Content = content
	// 将filenode数据marshal
	filenodeBytes, err := json.Marshal(filenode)
	if err != nil {
		return err
	}
	// 生成一个hash认证码
	hmacTag_filenode, EncryptedBytes, err := userdata.GenerateHmacTag(filenodeBytes)
	// 把filenode的content存储到filenode的UUID上
	userlib.DatastoreSet(filenode.UUID, append(EncryptedBytes, hmacTag_filenode...))
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	filelocator, err := userdata.DecryptFilelocator(filename)
	if err != nil {
		return nil, err
	}
	for _, UUID := range filelocator.FileNodeUUIDs {
		var filenode FileNode
		filenode_data, ok := userlib.DatastoreGet(UUID)
		if ok != true {
			return nil, errors.New("文件节点不对")
		}
		// 分理出newUserEncryted 和hamcTag
		newUserEncryted := filenode_data[:len(filenode_data)-64]
		hmacTag := filenode_data[len(filenode_data)-64:]
		// 来验证hmacTag是否一样
		// 生成堆成加密密钥和消息认证密码
		symEncKey, macKey := GenerateKeys(userdata.Username, userdata.Password)
		hmacTagVerify, hmacError := userlib.HMACEval(macKey, newUserEncryted)
		if hmacError != nil {
			return nil, errors.New("哈希消息认证失败")
		}
		if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
			return nil, errors.New("数据被修改或者密码错误")
		}
		//RSA解密数据
		Filenode_jsoned := userlib.SymDec(symEncKey, newUserEncryted)
		//获取filenode
		err_Marshal := json.Unmarshal(Filenode_jsoned, &filenode)
		if err_Marshal != nil {
			return nil, errors.New("UnMarshal失败")
		}
		content = append(content, filenode.Content...)
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//生成userdata的UUID
	hashUsername := userlib.Hash([]byte(userdata.Username))
	userdataUUID, err := uuid.FromBytes(hashUsername[:16])
	if err != nil {
		return uuid.Nil, err
	}
	//生成recipientUsername的UUID
	hashrecipientUsername := userlib.Hash([]byte(recipientUsername))
	recipientUsernameUUID, err := uuid.FromBytes(hashrecipientUsername[:16])
	if err != nil {
		return uuid.Nil, err
	}
	//生成filename的ID
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	//文件不存在
	if _, ok := userlib.DatastoreGet(storageKey); ok != true {
		return uuid.Nil, errors.New("文件不存在")
	}
	//被邀请用户名为空
	if len(recipientUsername) == 0 {
		return uuid.Nil, errors.New("被邀请用户名不能为空")
	}
	//邀请的用户不存在
	if _, ok := userlib.DatastoreGet(recipientUsernameUUID); ok != true {
		return uuid.Nil, errors.New("邀请的用户不存在")
	}
	//创建邀请码
	invitationPtr = uuid.New()
	//创建Invitationfile
	var invitationdata Invitationfile
	//生成Invitationfile的ID
	InvitationIDdata, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	invitationdata.InvitationID = invitationPtr
	// 创建分享树
	root := &TreeNode{}
	root.Father = nil
	root.Value = userdataUUID
	root.Friend = append(root.Friend, recipientUsernameUUID)
	invitationdata.InvitationTree = root
	//存储Invitationfile
	invitationdataBytes, err := json.Marshal(invitationdata)
	if err != nil {
		return uuid.Nil, errors.New("无法把Invitationfile转为byte流")
	}
	userlib.DatastoreSet(InvitationIDdata, invitationdataBytes)
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//生成senderUsername的UUID
	hashsenderUsername := userlib.Hash([]byte(senderUsername))
	senderUsernameUUID, err := uuid.FromBytes(hashsenderUsername[:16])
	if err != nil {
		return err
	}
	if _, ok := userlib.DatastoreGet(senderUsernameUUID); ok != true {
		return errors.New("发出分享的用户不存在")
	}
	//生成filename的ID
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(senderUsername + filename))[:16])
	if err != nil {
		return err
	}
	//文件不存在
	if _, ok := userlib.DatastoreGet(storageKey); ok != true {
		return errors.New("文件不存在")
	}
	//生成接收者UUID
	hashrecipientUsername := userlib.Hash([]byte(userdata.Username))
	recipientUsernameUUID, err := uuid.FromBytes(hashrecipientUsername[:16])
	if err != nil {
		return err
	}
	//找到Invitationfile
	//生成Invitationfile的ID
	InvitationIDdata, err := uuid.FromBytes(userlib.Hash([]byte(filename + senderUsername))[:16])
	if err != nil {
		return err
	}
	//索引
	InvitationfileJSON, ok := userlib.DatastoreGet(InvitationIDdata)
	if ok != true {
		return errors.New("Invitationfile不存在")
	}
	//导出
	var Invitationfiledata Invitationfile
	err_Marshal := json.Unmarshal(InvitationfileJSON, &Invitationfiledata)
	if err_Marshal != nil {
		return err_Marshal
	}
	if invitationPtr != Invitationfiledata.InvitationID {
		return errors.New("分享验证码错误或分享已被撤销")
	}
	if Contains(Invitationfiledata.InvitationTree.Friend, recipientUsernameUUID) {
		recipientUserTree := &TreeNode{}
		recipientUserTree.Father = Invitationfiledata.InvitationTree
		recipientUserTree.Value = recipientUsernameUUID
		Invitationfiledata.InvitationTree.Children = append(Invitationfiledata.InvitationTree.Children, recipientUserTree)
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//生成recipientUsername的UUID
	hashrecipientUsername := userlib.Hash([]byte(recipientUsername))
	recipientUsernameUUID, err := uuid.FromBytes(hashrecipientUsername[:16])
	if err != nil {
		return err
	}
	//生成filename的ID
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	if err != nil {
		return err
	}
	//文件不存在
	if _, ok := userlib.DatastoreGet(storageKey); ok != true {
		return errors.New("文件不存在")
	}
	//被撤销邀请用户名为空
	if len(recipientUsername) == 0 {
		return errors.New("被撤销邀请用户名不能为空")
	}
	//撤销邀请的用户不存在
	if _, ok := userlib.DatastoreGet(recipientUsernameUUID); ok != true {
		return errors.New("撤销邀请的用户不存在")
	}
	//找到Invitationfile
	//生成Invitationfile的ID
	InvitationIDdata, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	//索引
	InvitationfileJSON, ok := userlib.DatastoreGet(InvitationIDdata)
	if ok != true {
		return errors.New("Invitationfile不存在")
	}
	//导出
	var Invitationfiledata Invitationfile
	err_Marshal := json.Unmarshal(InvitationfileJSON, &Invitationfiledata)
	if err_Marshal != nil {
		return err_Marshal
	}
	//将分享验证码置零，Friend，Children数组剔除接收者
	Invitationfiledata.InvitationID = uuid.UUID{}
	Invitationfiledata.InvitationTree.Friend = RemoveFromSlice(Invitationfiledata.InvitationTree.Friend, recipientUsernameUUID)
	Invitationfiledata.InvitationTree.Children = RemoveFromTree(Invitationfiledata.InvitationTree.Children, recipientUsernameUUID)
	return nil
}
