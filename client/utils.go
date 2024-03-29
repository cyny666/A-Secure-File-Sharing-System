package client

import (
	"errors"
	userlib "github.com/cs161-staff/project2-userlib"
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
