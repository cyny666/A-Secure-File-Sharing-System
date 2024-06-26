### Information about Structs in DataStore

| Struct       | Enc/Mac              | UUID(用来存储到keystore中的)                                 | Contents                                                     | Description                                             |
| ------------ | -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------- |
| User         | Symmetric Key/HMAC   | uuid.FromBytes(Hash(Username)[:16])                          | Username,password,Private  key,Signature Key, and an IntermediateUUIDmap | 包含用户的所有信息，IntermediateUUIDmap包含所有的邀请者 |
| FileNode     | Symmetric Key/HMAC   | uuid.New()                                                   | File contents, PrevUUID,NextUUID                             | 文件节点储存在链表中                                    |
| FileLocator  | Symmetric Ket/HMAC   | uuid.FromBytes(userlib.Hash([]byte(userdata.Username + filename))[:16]) | FirstFileNodeUUID,LastFileNodeUUID,SymKeyFN,MacKeyFn         | 用来解析文件                                            |
| Intermediate | Symmetric Key/HMAC   | uuid.New()                                                   | FileLocatorUUID,SymKeyFileLocator,MacKeyFileLocator          | 文件的直接接受者                                        |
| Invitation   | HybridEncrytion/HMAC | uuid.New()                                                   | IntermediateUUID,SymKeyInter,MacKeyInter                     | 邀请别人的时候创造                                      |
| KeyFile      | Symmetric Key/HMAC   | uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "file"+filename))[:16]) | IsFileOwner bool,FileUUID,SymKeyFile,MacKeyFile              | 每一个用户如何获取其文件                                |


一些实现的细节（可以补充）：

user的uuid的生成方式: hash([]byte(username)) -> [:16] -> uuid.FromBytes

然后公钥存储Keystore的方式 : eystoreSet(username+"publicKey", publicKey)
