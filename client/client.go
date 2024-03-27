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
	Username      string
	Password      string
	Private_key   userlib.PKEEncKey
	Signature_key userlib.PKEDecKey
	// 这里对于Intermediate Id想以树的方式来定义
	IntermediateUUIDmap TreeNode
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// 文件存储的基本单元
type FileNode struct {
	Contents []byte
	PrevUUID uuid.UUID
	NextUUID uuid.UUID
}

// 包含文件对应的 FileNode 地址
type Filelocator struct {
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
	FileNode    uuid.UUID
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
	var userdata User
	userdata.Username = username
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
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

//#####################################################################################################################
//------------------------------------- 辅助函数：生成Keys -----------------------------------------------------------------------------------------------------------------
//#####################################################################################################################

// 根据用户名和密码生成密钥
func GenerateKeys(username string, password string) (encKey []byte, macKey []byte) {
	// userlib.Hash返回字节数组长度为64，这里取前16字节
	usernameHash := userlib.Hash([]byte(username))[:16]
	passwordHash := userlib.Hash([]byte(password))[:16]

	// Argon2Key is a slow hash function, designed specifically for hashing passwords.
	// func argon2Key(password []byte, salt []byte, keyLen uint32) []byte
	symmetricKey := userlib.Argon2Key(passwordHash, usernameHash, 32)
	encKey = symmetricKey[:16]
	macKey = symmetricKey[16:]

	return encKey, macKey
}

// 根据单个字符串生成密钥
func GenerateSymAndMacKey(purpose string) (sym []byte, mac []byte, err error) {
	// 获取随机16字节作为Key
	sourceKey := userlib.RandomBytes(16)
	key, err := userlib.HashKDF(sourceKey, []byte(purpose))
	if err != nil {
		return nil, nil, errors.New("something wrong with using HahsKDF to generate key")
	}
	symKey, macKey := key[:16], key[16:32]
	return symKey, macKey, nil
}

// 混合加密
func HybridEncryption(publicKey userlib.PKEEncKey, dataBytes []byte, purpose string) (encryptedSymKey []byte, encryptedDataBytes []byte, err error) {
	// 生成对称密钥
	symKey, _, _ := GenerateSymAndMacKey(purpose)
	// 解密对称密钥
	encryptedSymKey, err = userlib.PKEEnc(publicKey, symKey)
	if err != nil {
		return nil, nil, errors.New("cannot encrypt the random symmetric key by public key")
	}
	iv := userlib.RandomBytes(16)
	// 对数据使用对称加密
	encryptedDataBytes = userlib.SymEnc(symKey, iv, dataBytes)
	return encryptedSymKey, encryptedDataBytes, nil
}

// 混合解密
func HybridDecryption(privateKey userlib.PKEDecKey, symKeyEncrypted []byte, dataEncrypted []byte) (decryptedBytes []byte, err error) {
	// 通过私钥解密出对称密钥
	symKey, err := userlib.PKEDec(privateKey, symKeyEncrypted)
	if err != nil {
		return nil, errors.New("cannot decrypt the symKeyEncrypted using this privateKey")
	}
	// 使用对称密钥解密数据
	decryptedBytes = userlib.SymDec(symKey, dataEncrypted)
	return decryptedBytes, nil
}
