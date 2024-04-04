package client

import (
	"encoding/json"
	"errors"

	userlib "A-Secure-File-Sharing-System/userlib_client"

	"github.com/google/uuid"
)

// 用Argon2算法生成密钥
func GenerateKeys(username string, password string) (encKey []byte, macKey []byte) {
	// 取一下username和password的hash值
	usernameHash := userlib.Hash([]byte(username))[:16]
	passwordHash := userlib.Hash([]byte(password))[:16]
	// 利用Argon2算法生成密钥
	symmetricKey := userlib.Argon2Key(passwordHash, usernameHash, 32)
	encKey = symmetricKey[:16]
	macKey = symmetricKey[16:]

	return encKey, macKey
}

// 用哈希认证码来确保信息未被篡改过
func (userdata *User) GenerateHmacTag(content []byte) (hmacTag []byte, ciphertext []byte, err error) {
	// 生成堆成加密密钥和消息认证密码
	symEncKey, macKey := GenerateKeys(userdata.Username, userdata.Password)
	// 生成随机向量
	iv := userlib.RandomBytes(16)
	// 将文件内容加密
	newUserEncrypted := userlib.SymEnc(symEncKey, iv, content)
	hmac_Tag, err := userlib.HMACEval(macKey, newUserEncrypted)
	if err != nil {
		return nil, nil, errors.New("生成哈希认证码失败")
	}
	return hmac_Tag, newUserEncrypted, nil
}

// 用来解密filelocator
func (userdata *User) DecryptFilelocator(filename string) (filelocator FileLocator, err error) {
	// 获取一下该文件的storageKey
	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	// 获取对应的data
	data, ok := userlib.DatastoreGet(storageKey)
	if ok != true {
		return filelocator, errors.New("没找到该文件")
	}
	// 分理出newUserEncryted 和hamcTag
	newUserEncryted := data[:len(data)-64]
	hmacTag := data[len(data)-64:]
	// 来验证hmacTag是否一样
	// 生成堆成加密密钥和消息认证密码
	symEncKey, macKey := GenerateKeys(userdata.Username, userdata.Password)
	hmacTagVerify, hmacError := userlib.HMACEval(macKey, newUserEncryted)
	if hmacError != nil {
		return filelocator, errors.New("哈希消息认证失败")
	}
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return filelocator, errors.New("数据被修改或者密码错误")
	}
	//先解密数据
	Filelocator_jsoned := userlib.SymDec(symEncKey, newUserEncryted)
	//用私钥解密数据
	filelocator_data, err := userlib.PKEDec(userdata.Private_key, Filelocator_jsoned)
	if err != nil {
		return filelocator, err
	}
	var filelocator_1 FileLocator
	//获取filelocator
	err_Marshal := json.Unmarshal(filelocator_data, &filelocator_1)
	if err_Marshal != nil {
		return filelocator, err_Marshal
	}
	return filelocator_1, nil
}

// 将相应的filelocator存储到Datastore里面
func (userdata *User) StoreFilelocator(filelocator FileLocator, filename string) (err error) {
	// 生成filelocator的ID
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16])
	// 把文件存入filenode中
	if err != nil {
		return err
	}
	// 将content json序列化
	contentBytes, err := json.Marshal(filelocator)
	PublicKey, ok := userlib.KeystoreGet(userdata.Username + "publicKey")
	if ok != true {
		return errors.New("用户的公钥丢失了")
	}
	// 对locator_ciphertext用RSA进行加密
	ciphertext, err := userlib.PKEEnc(PublicKey, contentBytes)
	hmacTag, newUserEncrypted, err := userdata.GenerateHmacTag(ciphertext)
	if err != nil {
		return err
	}
	// 查找Datastore中是否存储有该userUUID
	if _, ok := userlib.DatastoreGet(storageKey); ok == false {
		return errors.New("您已经储存过该文件")
	}
	// 将哈希消息认证码和LocatorContent存储到这里
	newUserEncrypted = append(newUserEncrypted, hmacTag...)
	userlib.DatastoreSet(storageKey, newUserEncrypted)
	return nil
}

func Contains(slice []uuid.UUID, s uuid.UUID) bool {
	for _, value := range slice {
		if value == s {
			return true
		}
	}
	return false
}

func RemoveFromSlice(slice []uuid.UUID, elem uuid.UUID) []uuid.UUID {
	var result []uuid.UUID

	// 遍历原始切片
	for _, v := range slice {
		// 如果元素不等于要移除的元素，将其添加到结果切片中
		if v != elem {
			result = append(result, v)
		}
	}

	return result
}

func RemoveFromTree(Children []*TreeNode, Value uuid.UUID) []*TreeNode {
	var result []*TreeNode

	// 遍历原始切片
	for _, v := range Children {
		// 如果元素不等于要移除的元素，将其添加到结果切片中
		if v.Value != Value {
			result = append(result, v)
		}
	}

	return result
}

func DFS(root *TreeNode, target uuid.UUID) *TreeNode {
	// 如果当前节点为nil，返回nil
	if root == nil {
		return nil
	}
	// 如果当前节点的值匹配目标值，返回当前节点
	if root.Value == target {
		return root
	}
	// 递归地在当前节点的子节点中搜索
	for _, child := range root.Children {
		if result := DFS(child, target); result != nil {
			return result
		}
	}
	// 如果在子节点中未找到匹配的节点，则返回nil
	return nil
}
