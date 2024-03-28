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

	// Useful for string manipulation
	"strings"

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
	Value    int
	Children []*TreeNode
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
	Contents []byte
	PrevUUID uuid.UUID
	NextUUID uuid.UUID
}

// 包含文件对应的 FileNode 地址
type FileLocator struct {
	FirstFileNodeUUID uuid.UUID
	LastFileNodeUUID  uuid.UUID
	SymKeyFn          []byte
	MacKeyFn          []byte
}

// 文件分享接收者通过 Intermediate 获取 fileLocator 的解密密钥
type Intermediate struct {
	FileLocatorUUID   uuid.UUID
	SymKeyFileLocator []byte
	MacKeyFileLocator []byte
}

// 每个用户通过 keyFile 来打开 file
type KeyFile struct {
	isFileOwner bool
	FileUUID    uuid.UUID
	SymKeyFile  []byte
	MacKeyFile  []byte
}

// 文件分享邀请
type Invitation struct {
	IntermediateUUID uuid.UUID
	SymKeyInter      []byte
	MacKeyInter      []byte
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
	// 生成堆成加密密钥和消息认证密码
	symEncKey, macKey := GenerateKeys(username, password)
	// 生成随机向量
	iv := userlib.RandomBytes(16)
	// 将数据加密
	newUserEncrypted := userlib.SymEnc(symEncKey, iv, userdataBytes)
	hmacTag, err := userlib.HMACEval(macKey, newUserEncrypted)
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
	if err != nil {
		return nil, err_Marshal
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
