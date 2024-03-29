package client

import (
	"encoding/json"
	"errors"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

// 用Argon2算法生成密钥
func GenerateKeys(username string, password string) (encKey []byte, macKey []byte) {
	usernameHash := userlib.Hash([]byte(username))[:16]
	passwordHash := userlib.Hash([]byte(password))[:16]
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

// 创建 Intermediate 结构体，并上传到 datastore
func EncIntermediate(symKeyInter []byte, macKeyInter []byte, thisIntermediateUUID uuid.UUID, fileLocatorUUID uuid.UUID, symKeyFileLocator []byte, macKeyFileLocator []byte) (err error) {
	// 构造 Intermediate 结构体
	intermediate := Intermediate{fileLocatorUUID, symKeyFileLocator, macKeyFileLocator}
	// 进行json序列化
	intermediateBytes, errMarshal := json.Marshal(intermediate)
	if errMarshal != nil {
		return errors.New("marshal error, cannot convert intermediate struct to bytes")
	}

	// 使用 Symmectric key 进行加密，使用 Mac Key 生成 hmac
	iv := userlib.RandomBytes(16)
	intermediateEncrypted := userlib.SymEnc(symKeyInter, iv, intermediateBytes)
	hmacTag, hmacError := userlib.HMACEval(macKeyInter, intermediateBytes)
	if hmacError != nil {
		return errors.New("input as key for hmac should be a 16-byte key")
	}
	userlib.DatastoreSet(thisIntermediateUUID, append(intermediateEncrypted, hmacTag...))

	return nil
}

// 创建 FileLocator 结构体，并上传到 datastore
func EncFileLocator(symKeyFL []byte, macKeyFL []byte, fileLocatorUUID uuid.UUID, FirstFileNodeUUID uuid.UUID, LastFileNodeUUID uuid.UUID, symKeyFN []byte, macKeyFN []byte) (err error) {
	// 构造 Intermediate 结构体
	fileLocator := FileLocator{FirstFileNodeUUID, LastFileNodeUUID, symKeyFN, macKeyFN}
	// 进行json序列化
	fileLocatorBytes, errMarshal := json.Marshal(fileLocator)
	if errMarshal != nil {
		return errors.New("marshal error, cannot convert User struct to bytes")
	}

	// 使用 Symmectric key 进行加密，使用 Mac Key 生成 hmac
	iv := userlib.RandomBytes(16)
	fileLocatorEncrypted := userlib.SymEnc(symKeyFL, iv, fileLocatorBytes)
	hmacTag, hmacError := userlib.HMACEval(macKeyFL, fileLocatorBytes)
	if hmacError != nil {
		return errors.New("input as key for hmac should be a 16-byte key")
	}
	userlib.DatastoreSet(fileLocatorUUID, append(fileLocatorEncrypted, hmacTag...))

	return nil
}

// 创建 FileNode 结构体，并上传到 datastore
func EncFileNode(sym []byte, mac []byte, content []byte, nodeUUID uuid.UUID, prevUUID uuid.UUID, nextUUID uuid.UUID) (err error) {
	// 创建 FileNode 结构体
	newNode := FileNode{content, prevUUID, nextUUID}
	// json序列化转化为字节
	newNodeBytes, errMarshal := json.Marshal(newNode)
	if errMarshal != nil {
		return errors.New("marshal error, cannot convert FileNode struct to bytes")
	}

	// 加密 fileNodeByte
	symEncKey, hmacKey := GenerateKeys(string(sym[:])+string(nodeUUID[:]), string(mac[:])+string(nodeUUID[:]))
	iv := userlib.RandomBytes(16)
	newFileNodeEncrypted := userlib.SymEnc(symEncKey, iv, newNodeBytes)

	// 使用加密的fileNode生成hmac
	hmacTag, hmacError := userlib.HMACEval(hmacKey, newFileNodeEncrypted)
	if hmacError != nil {
		return errors.New("input as key for hmac should be a 16-byte key")
	}

	// 将加密的FileNode和hamcTag存储到datastore中
	userlib.DatastoreSet(nodeUUID, append(newFileNodeEncrypted, hmacTag...))

	return nil
}

// 验证并解密获取 Intermediate
func VerifyThenDecIntermediate(symKey []byte, macKey []byte, interUUID uuid.UUID) (IntermediatePtr *Intermediate, err error) {
	dataValue, ok := userlib.DatastoreGet(interUUID)
	if !ok {
		return nil, errors.New("The File doesnot exist / Or you has been revoked")
	}
	//need to verify and decrypt file node
	encryptedFile, hmacTag := dataValue[:len(dataValue)-64], dataValue[len(dataValue)-64:]
	hmacTagVerify, hmacError := userlib.HMACEval(macKey, encryptedFile)
	if hmacError != nil {
		return nil, errors.New("Cannot create a tag for Intermediate")
	}

	// Confirm authenticity using HMACEqual()
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return nil, errors.New("Intermediate has been tampered / Or you has been revoked")
	}

	// Decrypt
	decryptedFileLocatorBytes := userlib.SymDec(symKey, encryptedFile)
	errMarshal := json.Unmarshal(decryptedFileLocatorBytes, &IntermediatePtr)
	if errMarshal != nil {
		return nil, errors.New("Unmarshal error, cannot convert bytes")
	}

	return IntermediatePtr, nil
}

// 验证并解密获取 FileLocator
func VerifyThenDecFileLocator(symKeyFL []byte, macKeyFL []byte, fileLocatorUUID uuid.UUID) (fileLocatorPtr *FileLocator, err error) {
	dataValue, ok := userlib.DatastoreGet(fileLocatorUUID)
	fmt.Println("VerifyThenDecFileLocator")
	fmt.Println(fileLocatorUUID)
	if ok != true {
		return nil, errors.New("The FileLocator doesnot exist")
	}
	//need to verify and decrypt file node
	encryptedFileLocator, hmacTag := dataValue[:len(dataValue)-64], dataValue[len(dataValue)-64:]
	hmacTagVerify, hmacError := userlib.HMACEval(macKeyFL, encryptedFileLocator)
	if hmacError != nil {
		return nil, errors.New("Cannot create a tag for encryptedFileLocator")
	}

	// Confirm authenticity using HMACEqual()
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return nil, errors.New("FileLocator has been modified, tampered")
	}

	// Decrypt
	decryptedFileLocatorBytes := userlib.SymDec(symKeyFL, encryptedFileLocator)
	var decryptedFileLocator FileLocator
	errMarshal := json.Unmarshal(decryptedFileLocatorBytes, &decryptedFileLocator)
	if errMarshal != nil {
		return nil, errors.New("Unmarshal error, cannot convert bytes to User Struct decryptAndVerifyFileNode()")
	}

	return &decryptedFileLocator, nil
}

// 验证并解密获取 FileNode
func VerifyThenDecFileNode(sym []byte, mac []byte, nodeUUID uuid.UUID) (fileNodePtr *FileNode, err error) {
	currFileNodeData, ok := userlib.DatastoreGet(nodeUUID)
	if !ok {
		return nil, errors.New("UUID(the fileNode) does not exists in DataStore")
	}

	//Retrieve/separate the encryptedFileNode and its hmac
	encryptedFileNode := currFileNodeData[:len(currFileNodeData)-64]
	hmacTag := currFileNodeData[len(currFileNodeData)-64:]

	//regenrate key and recreate hmac tag to verify
	symEncKey, hmacKey := GenerateKeys(string(sym[:])+string(nodeUUID[:]), string(mac[:])+string(nodeUUID[:]))
	hmacTagVerify, hmacError := userlib.HMACEval(hmacKey, encryptedFileNode)
	if hmacError != nil {
		return nil, errors.New("input as key for hmac should be a 16-byte key")
	}

	// Confirm authenticity using HMACEqual()
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return nil, errors.New("filedataNode has been modified")
	}

	// decrypt file node
	decryptedFileNodeBytes := userlib.SymDec(symEncKey, encryptedFileNode)
	var decryptedFileNode FileNode
	errMarshal := json.Unmarshal(decryptedFileNodeBytes, &decryptedFileNode)
	if errMarshal != nil {
		return nil, errors.New("Unmarshal error, cannot convert bytes to Struct")
	}

	return &decryptedFileNode, nil
}

//############# *User 成员函数##############

// 获取指定文件的 FileLocator
func (userdata *User) GetFileLocator(filename string) (id uuid.UUID, sym []byte, mac []byte, err error) {
	// 解密KEYFILE以获得文件的密钥和uuid(文件可以是fileLocator或Intermediate)
	keyFile, err := userdata.VerifyThenDecKeyFile(filename)

	// KeyFile 不存在
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	// KeyFile 包含 fileLocatorUUID
	if keyFile.isFileOwner {
		return keyFile.FileUUID, keyFile.SymKeyFile, keyFile.MacKeyFile, nil
	}

	// KeyFile 包含 intermediateUUID
	Intermediate, err := VerifyThenDecIntermediate(keyFile.SymKeyFile, keyFile.MacKeyFile, keyFile.FileUUID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	return Intermediate.FileLocatorUUID, Intermediate.SymKeyFileLocator, Intermediate.MacKeyFileLocator, nil
}

// 创建 KeyFile 结构体，并上传到 datastore
func (userdata *User) EncKeyFile(filename string, isFileOwner bool, fileUUID uuid.UUID, symKeyF []byte, macKeyF []byte) (err error) {
	// Store the 2 keys sym and mac for the file in KeyFile Struct
	keyFile := KeyFile{isFileOwner, fileUUID, symKeyF, macKeyF}
	keyFileBytes, errMarshal := json.Marshal(keyFile)
	if errMarshal != nil {
		return errors.New("Marshal error, cannot convert User Struct to bytes")
	}

	// Generate symmetricKey and macKey from username and file to Encrypt then Tag
	symEncKey, macKey := GenerateKeys(userdata.Username, filename)
	iv := userlib.RandomBytes(16)
	keyFileEncrypted := userlib.SymEnc(symEncKey, iv, keyFileBytes)
	hmacTag, hmacError := userlib.HMACEval(macKey, keyFileEncrypted)
	if hmacError != nil {
		return errors.New("input as key for hmac should be a 16-byte key")
	}
	// Store the new keyFileUUID to datastore
	keyFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "file" + filename))[:16])
	userlib.DatastoreSet(keyFileUUID, append(keyFileEncrypted, hmacTag...))

	return nil
}

// 验证并解密获取 KeyFile
func (userdata *User) VerifyThenDecKeyFile(filename string) (keyfilePtr *KeyFile, err error) {
	// 根据 username + filename 获取 keyFileUUID
	keyFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "file" + filename))[:16])
	if err != nil {
		return nil, errors.New("failed to get keyFileNode from username+filename")
	}
	dataValue, ok := userlib.DatastoreGet(keyFileUUID)
	// Error: keyFileUUID 不存在
	if ok == false {
		return nil, errors.New("keyFileUUID dose not exists in DataStore")
	}

	// 获取 keyFileEncrypted
	keyFileEncrypted := dataValue[:len(dataValue)-64]
	// 获取 hmacTag
	hmacTag := dataValue[len(dataValue)-64:]

	// 从用户名和文件名生成symmetricKey和macKey来验证TAG和DECRYPT
	symEncKey, macKey := GenerateKeys(userdata.Username, filename)
	hmacTagVerify, hmacError := userlib.HMACEval(macKey, keyFileEncrypted)
	if hmacError != nil {
		return nil, errors.New("input as key for hmac should be a 16-byte key")
	}

	// 使用HMACEqual（）确认KeyFile的完整性
	if !userlib.HMACEqual(hmacTagVerify, hmacTag) {
		return nil, errors.New("keyFile has been modified")
	}

	// 解密 KeyFile
	decryptedKeyFileBytes := userlib.SymDec(symEncKey, keyFileEncrypted)
	var decryptedKeyFile KeyFile
	// 反序列化：json -> KeyFile struct
	errMarshal := json.Unmarshal(decryptedKeyFileBytes, &decryptedKeyFile)
	if errMarshal != nil {
		return nil, errors.New("Unmarshal error, cannot convert bytes to Struct")
	}

	return &decryptedKeyFile, nil
}
