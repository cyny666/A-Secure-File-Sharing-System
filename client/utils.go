package client

import userlib "github.com/cs161-staff/project2-userlib"

// 用Argon2算法生成密钥
func GenerateKeys(username string, password string) (encKey []byte, macKey []byte) {
	usernameHash := userlib.Hash([]byte(username))[:16]
	passwordHash := userlib.Hash([]byte(password))[:16]
	symmetricKey := userlib.Argon2Key(passwordHash, usernameHash, 32)
	encKey = symmetricKey[:16]
	macKey = symmetricKey[16:]
	return encKey, macKey
}
