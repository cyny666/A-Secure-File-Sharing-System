### Information about Structs in DataStore

| Struct       | Enc/Mac              | UUID                                                         | Contents                                                     | Description                                             |
| ------------ | -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------- |
| User         | Symmetric Key/HMAC   | uuid.FromBytes(Hash(Username)[:16])                          | Username,password,Private  key,Signature Key, and an IntermediateUUIDmap | 包含用户的所有信息，IntermediateUUIDmap包含所有的邀请者 |
| FileNode     | Symmetric Key/HMAC   | uuid.New()                                                   | File contents, PrevUUID,NextUUID                             | 文件节点储存在链表中                                    |
| FileLocator  | Symmetric Ket/HMAC   | uuid.New()                                                   | FirstFileNodeUUID,LastFileNodeUUID,SymKeyFN,MacKeyFn         | 用来解析文件                                            |
| Intermediate | Symmetric Key/HMAC   | uuid.New()                                                   | FileLocatorUUID,SymKeyFileLocator,MacKeyFileLocator          | 文件的直接接受者                                        |
| Invitation   | HybridEncrytion/HMAC | uuid.New()                                                   | IntermediateUUID,SymKeyInter,MacKeyInter                     | 邀请别人的时候创造                                      |
| KeyFile      | Symmetric Key/HMAC   | uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "file"+filename))[:16]) | IsFileOwner bool,FileUUID,SymKeyFile,MacKeyFile              | 每一个用户如何获取其文件                                |


### Datastore中数据如何存储

- 主要使用Structs
- 对struct中的内容进行加密，再使用MAC以保证完整性

- - MAC：Message　Authentication Code 消息认证码，用于验证消息的完整性和认证消息的来源

- User Struct: 包含用户消息
- FileNode Struct nodes以链表数据结构形式存在
- file sharing and revocaiton: Invitation, KeyFile, Imtermediate, FileLocator Structs

### 除加密函数以外的辅助函数

- 对Datastore中structs加解密的辅助函数
- HybridEncryption/HybridDecryption: 执行混合加密以存储 invitational structs
- EncFileNode/VerifyThenDecFileNode: 对 file nodes 的对称加密，解密时使用 hmacs 进行完整性检查
- GenerateKeys: 为加密过程/hmac创建keys

### 如何进行用户身份认证

- 每个user struct 拥有一个与用户名的哈希值相关的 unique UUID 
- 进行用户认证时：

- - 首先，根据用户名创建UUID，并检查datastore中是否存在该UUID（用户名是unique的）
  - 进一步验证密码
  - 只有在用户名和密码匹配的情况下，才能重新创建正确的对称密钥和mac密钥

### 如何保证不同设备上同一用户的多个对象总是反映着该用户的最新改变

- 远程datastore存储着用户数据的最新状态
- 当一个用户对象发生改变，从远程datastore下载用户对象，解密，进行对应的改变，加密更新后的数据，存储到远程datastore
- 因此，总是能从远程datastore中下载到最新更新的用户对象

### 用户如何存储和检索文件

- 用户文件以 FileNode 的链表形式存储
- 每个 FileNode 包含 内容字节（由文件内容决定），链表中下一个 FileNode 的UUID，链表中上一个 FileNode 的UUID
- 另外还定义的 FileLocator 结构，包含 链表中的第一个和最后一个 FileNode 的UUID，以及 keys（用于加解密 FileNodes）
- 当用户存储一个新的文件，第一个 FileNode 会被填充数据内容，而最后一个 FileNode 为空
- 检索文件：

- - 通过该文件的 FileLocator 定位到第一个 FileNode
  - 一边迭代遍历，一边将将节点内容加到结果中
  - 最终，结果内容即为文件内容

### 一次 append 调用的总带宽

- 总带宽 = 添加的数据的大小 + 常数（一个空的FileNode和FileLocator的大小）
- append 过程：

- - 下载文件对应的 FileLocator（包含文件最后一个空的FileNode）
  - 修改最后一个 FileNode，填充添加的数据（可能需要添加额外的 FileNode）
  - 添加新的空的 FileNode 作为链表的终点

### 调用CreateInvitation会创建什么

- 如果邀请发送者是文件的拥有者：会创建 1个 intermediate struct，1个invitation struct

- - intermediate struct 包含 FileLocator 的 UUID，用于解密的 keys
  - invitation struct 包含 intermediate struct 的 UUID，用于解密的 keys

- 如果不是：仅会创建1个 invitation struct

- - invitation struct 包含 发送者的 intermediate struct 的 UUID

- CreateInvitation 会返回 invitation struct 的 UUID

### 调用 AcceptInvitation会发生什么变化

- 用户会接收到 invitation struct 的 UUID，同时用于对它进行解密和访问内部信息的能力
- 1个KeyFile会被创建，KeyFile仅用户能够访问，包含 intermediate struct 的 UUID 和用于解密的 keys（因此能够访问文件数据）

### 当调用 revoke 时会更新什么值

- FileNodes 的内容会被下载，并存储到新的FileNode中
- 删除旧的 FileLocator， 替换为新的 FileLocator（拥有新的UUID，更新的 key 值，指向信道 FileNode）
- 需要更新所有指向文件的 intermediate nodes（未被revoke的用户）
- 所有 revoked user 的 intermediate struct 直接删除


一些实现的细节（可以补充）：

user的uuid的生成方式: hash([]byte(username)) -> [:16] -> uuid.FromBytes

然后公钥存储Keystore的方式 : eystoreSet(username+"publicKey", publicKey)
