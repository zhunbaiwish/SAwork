# ABE/IBE 模块化接口文档

## 目录结构

```
/mnt/e/SAwork/
├── dockerfile          # Docker 构建配置
├── docs/              # 文档
├── abe/               # ABE 模块
│   ├── CMakeLists.txt
│   ├── a.param                     # PBC 配对参数文件
│   ├── serverInteraction.proto      # ABE gRPC 协议定义
│   ├── lib/abe_core/              # ABE 核心库
│   │   ├── CMakeLists.txt
│   │   ├── include/
│   │   │   ├── CPABE.h
│   │   │   ├── CPABE_types.h
│   │   │   ├── CPABE_core.h
│   │   │   ├── CPABE_access.h
│   │   │   ├── CPABE_serialize.h
│   │   │   ├── CPABE_utils.h
│   │   │   ├── parse.h
│   │   │   ├── json.hpp
│   │   │   └── abe/authority.h     # 属性权威类
│   │   └── *.cpp
│   └── demos/
│       ├── direct/                 # 直接接口调用示例
│       │   ├── CMakeLists.txt
│       │   ├── server.cpp          # 生成密钥并保存到 .bin 文件
│       │   └── client.cpp          # 从文件加载密钥进行加解密
│       └── grpc/                   # gRPC 远程调用示例
│           ├── CMakeLists.txt
│           ├── server.cpp          # gRPC 服务器
│           └── client.cpp          # gRPC 客户端
└── ibe/                          # IBE 模块
    ├── CMakeLists.txt
    ├── ibe.proto                  # IBE gRPC 协议定义
    ├── lib/ibe_core/              # IBE 核心库
    │   ├── CMakeLists.txt
    │   ├── sm9_ibe.h/cpp          # SM9 IBE 实现
    │   ├── sm9_ibs.h/cpp          # SM9 IBS 实现
    │   ├── io.h                   # 文件读写工具
    │   ├── pkg_service.cpp        # PKG 服务实现
    │   └── include/
    │       └── ibe/pkg_service.h   # PKG 服务接口
    └── demos/
        ├── direct/                # 直接接口调用示例
        │   ├── CMakeLists.txt
        │   ├── server.cpp         # 生成密钥
        │   └── client.cpp        # 加解密、签名验签
        └── grpc/                 # gRPC 远程调用示例
            ├── CMakeLists.txt
            ├── server.cpp
            └── client.cpp
```

---

## 1. ABE 模块

### 1.1 authority.h - 属性权威核心类

```cpp
#include "CPABE_types.h"
#include "CPABE_utils.h"
#include "CPABE_access.h"
#include "CPABE_core.h"
#include "CPABE_serialize.h"
#include "parse.h"

namespace abe {

class AttributeAuthority {
public:
    AttributeAuthority();
    ~AttributeAuthority();

    /**
     * @brief 初始化属性权威
     * @param param_file pairing参数文件路径（如"a.param"）
     * @param max_attrs 最大属性数量
     * @return 初始化是否成功
     */
    bool initialize(const std::string& param_file, int max_attrs);

    /**
     * @brief 获取公钥（JSON格式）
     * @param layer 层级（1, 2, ...）
     * @return 公钥的JSON字符串，用于网络传输
     */
    std::string get_public_key_json(int layer);

    /**
     * @brief 生成私钥（JSON格式）
     * @param layer 层级
     * @param attrs 属性列表
     * @return 私钥的JSON字符串，用于网络传输
     */
    std::string generate_private_key_json(int layer,
                                          const std::vector<std::string>& attrs);

    /**
     * @brief 转换策略表达式
     * @param layer 层级
     * @param policy 原始策略表达式（如"(role:admin AND clearance:high)"）
     * @return 转换后的策略字符串
     */
    std::string convert_policy(int layer, const std::string& policy);

    /**
     * @brief 设置属性映射
     * @param layer 层级
     * @param attr_map 属性名到ID的映射
     */
    void set_attribute_map(int layer,
                           const std::unordered_map<std::string, int>& attr_map);

    /**
     * @brief 获取配对对象指针（用于客户端序列化）
     */
    pairing_t* get_pairing();
};

// ============ 辅助函数 ============

/**
 * @brief 从JSON字符串加载公钥
 */
CP_ABE_PK json_to_cpabe_pk(const std::string& json_str, pairing_t pairing);

/**
 * @brief 将私钥转为JSON字符串
 */
std::string cpabe_sk_to_json_str(CP_ABE_SK& sk);

/**
 * @brief 从JSON字符串加载私钥
 */
CP_ABE_SK json_to_cpabe_sk(const std::string& json_str, pairing_t pairing);

}  // namespace abe
```

#### 使用示例（直接接口）

```cpp
#include "abe/authority.h"
#include "CPABE_serialize.h"

using namespace abe;

// 创建属性权威实例
AttributeAuthority aa;

// 初始化
if (!aa.initialize("a.param", 3)) {
    std::cerr << "初始化失败" << std::endl;
    return;
}

// 自定义属性映射，map大小必须与初始化的数字3大小相同
std::unordered_map<std::string, int> attr_map = {
    {"role:admin", 1},
    {"role:user", 2},
    {"dept:IT", 3}
};
aa.set_attribute_map(1, attr_map);

// 获取公钥JSON并保存为二进制文件
std::string pk_json = aa.get_public_key_json(1);
CP_ABE_PK pk = json_to_cpabe_pk(pk_json, *aa.get_pairing());
serializeToFile(pk, "abe_public_key_1.bin");

// 生成私钥JSON并保存为二进制文件
std::vector<std::string> attrs = {"role:admin", "dept:IT"};
std::string sk_json = aa.generate_private_key_json(1, attrs);
CP_ABE_SK sk = json_to_cpabe_sk(sk_json, *aa.get_pairing());
serializeToFile(sk, "abe_secret_key_1.bin");

// 转换策略
std::string policy = "(role:admin AND dept:IT) OR role:user";
std::string converted = aa.convert_policy(1, policy);
```

### 1.2 ABE Proto - serverInteraction.proto

```protobuf
service AttributeAuthorityService {
    rpc GetABEPublicKey(GetABEPublicKeyRequest) returns(GetABEPublicKeyResponse);
    rpc GetABEPrivateKey(GetABEPrivateKeyRequest) returns(GetABEPrivateKeyResponse);
    rpc ConvertPolicy(ConvertPolicyRequest) returns(ConvertPolicyResponse);
}

message GetABEPublicKeyRequest {
    int32 key_id = 1;  // 1: 第一层公钥, 2: 第二层公钥
}

message GetABEPublicKeyResponse {
    string abe_public_key = 1;  // JSON 格式
}

message GetABEPrivateKeyRequest {
    int32 layer = 1;
    repeated string attrs = 2;
}

message GetABEPrivateKeyResponse {
    string abe_secret_key = 1;  // JSON 格式
}

message ConvertPolicyRequest {
    int32 layer = 1;
    string policy = 2;
}

message ConvertPolicyResponse {
    string converted_policy = 1;
}
```

### 1.3 ABE 加解密接口（原有接口）

```cpp
#include "CPABE.h"

// 初始化配对
pairing_t pairing;
init_pairing(pairing, "a.param");

// 初始化公钥/私钥结构
CP_ABE_PK pk;
CP_ABE_MSK msk;
CP_ABE_SK sk;

init_CP_ABE_PK(pk, 2);//

// Setup - 生成主密钥
cpabe_Setup(pk, msk, pairing);

// Keygen - 生成用户私钥
int auth[] = {'A', 'B', 0};  // 属性数组
cpabe_Keygen(sk, auth, pk, msk, pairing);

// Encrypt - 加密
int Access[] = {2, 1, -'A', -'B', 0};  // 访问策略，属性的个数必须与初始化的大小相同
unsigned char plaintext[32] = "secret message...";
CT ct;
cpabe_Encrypt(Access, plaintext, ct, pk, pairing);

// Decrypt - 解密
unsigned char* dec_data;
cpabe_Decrypt(Access, pairing, ct, sk, dec_data);

// 序列化/反序列化
serializeToFile(ct, "ciphertext.bin");
deSerializeFromFile(ct, "ciphertext.bin", pairing);
```

---

## 2. IBE 模块

### 2.1 SM9_IBE 类

```cpp
#include "sm9_ibe.h"

class SM9_IBE {
public:
    SM9_IBE();
    ~SM9_IBE();

    // 生成主密钥（PKG使用）
    bool generate_master_key(const std::string& master_key_file);

    // 保存/加载主公钥
    bool save_master_public(const std::string& pub_file);
    bool load_master_public(const std::string& pub_file);
    bool load_master_public_der(const std::vector<uint8_t>& der);

    // 生成用户私钥（PKG使用）
    bool generate_user_private_key(const std::string& user_id,
                                   const std::string& user_key_file);

    // 导出用户私钥为DER（用于网络传输）
    bool export_user_private_key_der(const std::string& user_id,
                                     std::vector<uint8_t>& out_der);

    // 加密
    bool encrypt(const std::string& user_id,
                 const std::vector<unsigned char>& plaintext,
                 std::vector<unsigned char>& ciphertext);

    // 解密（使用文件私钥）
    bool decrypt(const std::string& user_id,
                 const std::string& user_key_file,
                 const std::vector<unsigned char>& ciphertext,
                 std::vector<unsigned char>& plaintext);

    // 解密（使用DER私钥）
    bool decrypt_with_user_private_der(const std::vector<uint8_t>& user_priv_der,
                                       const std::string& user_id,
                                       const std::vector<unsigned char>& ciphertext,
                                       std::vector<unsigned char>& plaintext);
};
```

#### 使用示例（直接接口）

```cpp
#include "sm9_ibe.h"
#include "sm9_ibs.h"

const std::string user_id = "user@example.com";

// ============ PKG 端 ============
SM9_IBE pkg;
pkg.generate_master_key("sm9_ibe_master.key");
pkg.save_master_public("sm9_ibe_master.pub");

// 导出用户私钥（通过网络发送）
std::vector<uint8_t> user_priv_der;
pkg.export_user_private_key_der(user_id, user_priv_der);

// ============ 发送方 ============
SM9_IBE sender;
std::vector<uint8_t> mpk_der;
read_file("sm9_ibe_master.pub", mpk_der);
sender.load_master_public_der(mpk_der);

std::string plaintext = "Hello, SM9 IBE!";
std::vector<unsigned char> pt(plaintext.begin(), plaintext.end());
std::vector<unsigned char> ciphertext;
sender.encrypt(user_id, pt, ciphertext);

// ============ 接收方 ============
SM9_IBE receiver;
std::vector<unsigned char> decrypted;
receiver.decrypt_with_user_private_der(user_priv_der, user_id, ciphertext, decrypted);
```

### 2.2 SM9_IBS 类

```cpp
#include "sm9_ibs.h"

class SM9_IBS {
public:
    SM9_IBS();
    ~SM9_IBS();

    // 生成签名主密钥
    bool generate_master_key(const std::string& master_key_file = "sm9_ibs_master.key");

    // 保存/加载签名公钥
    bool save_master_public(const std::string& pub_file = "sm9_ibs_master.pub");
    bool load_master_public(const std::string& pub_file);

    // 生成用户签名私钥
    bool generate_user_private_key(const std::string& user_id,
                                  const std::string& user_key_file);

    // 导出签名私钥为DER
    bool export_user_private_key_der(const std::string& user_id,
                                     std::vector<uint8_t>& out_der);

    // 签名（使用文件私钥）
    bool sign(const std::string& user_key_file,
              const std::vector<unsigned char>& message,
              std::vector<uint8_t>& signature);

    // 签名（使用DER私钥）
    bool sign_with_der(const std::vector<uint8_t>& user_priv_der,
                       const std::vector<unsigned char>& message,
                       std::vector<uint8_t>& signature);

    // 验签
    bool verify(const std::string& user_id,
               const std::vector<unsigned char>& message,
               const std::vector<uint8_t>& signature);
};
```

### 2.3 IBE Proto - ibe.proto

```protobuf
syntax = "proto3";
package ibe;

import "google/protobuf/empty.proto";

service IbeService {
    rpc GetIBEMasterPublic(google.protobuf.Empty) returns (MasterPub);
    rpc GetIBEUserPrivateKey(UserId) returns (UserPriv);
    rpc GetIBSMasterPublic(google.protobuf.Empty) returns (MasterPub);
    rpc GetIBSUserPrivateKey(UserId) returns (UserPriv);
}

message MasterPub {
    bytes der = 1;
}

message UserId {
    string id = 1;
}

message UserPriv {
    bytes der = 1;
}
```

---

## 3. Proto 定义

Proto 文件位于各模块根目录：

| 模块 | Proto 文件路径 |
|------|---------------|
| ABE | `abe/serverInteraction.proto` |
| IBE | `ibe/ibe.proto` |

生成命令：
```bash
# ABE
protoc --cpp_out=. --grpc_out=. --plugin=protoc-gen-grpc=grpc_cpp_plugin \
    -I../.. serverInteraction.proto

# IBE
protoc --cpp_out=. --grpc_out=. --plugin=protoc-gen-grpc=grpc_cpp_plugin \
    -I../.. ibe.proto
```

---

## 4. 示例程序结构

### Direct 模式

- **server.cpp**: 生成密钥对、用户私钥，保存到文件
- **client.cpp**: 从文件加载密钥，进行加解密操作

### gRPC 模式

- **server.cpp**: 运行 gRPC 服务器，远程提供密钥分发服务
- **client.cpp**: 通过 gRPC 请求密钥，然后进行加解密操作

---

## 5. 编译链接

各模块 CMakeLists.txt 已配置好依赖路径，直接使用：

```cmake
# ABE
target_link_libraries(your_app abe_core)

# IBE
target_link_libraries(your_app ibe_core)
```
