package client

import (
	"errors"
	userlib "github.com/cs161-staff/project2-userlib"
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
