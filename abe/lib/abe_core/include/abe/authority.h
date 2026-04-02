#ifndef ABE_AUTHORITY_H
#define ABE_AUTHORITY_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include "CPABE_types.h"
#include "CPABE_utils.h"
#include "CPABE_access.h"
#include "CPABE_core.h"
#include "CPABE_serialize.h"
#include "parse.h"

// forward declarations
void init_CP_ABE_PK(CP_ABE_PK &pk, int nums);
void init_CP_ABE_SK(CP_ABE_SK &sk, int nums);
void cpabe_Setup(CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p);
void cpabe_Keygen(CP_ABE_SK &sk, int *auth, CP_ABE_PK &pk, CP_ABE_MSK &msk, pairing_t p);

namespace abe {

// 属性权威服务类 - 封装ABE核心业务逻辑
class AttributeAuthority {
public:
    AttributeAuthority();
    ~AttributeAuthority();

    // 初始化（配对参数、密钥生成）
    // param_file: pairing参数文件路径
    // max_attrs: 最大属性数量
    bool initialize(const std::string& param_file, int max_attrs);

    // 获取公钥（JSON格式，用于网络传输）
    // layer: 层级（1, 2, ...）
    std::string get_public_key_json(int layer);

    // 生成私钥（JSON格式，用于网络传输）
    // layer: 层级
    // attrs: 属性列表
    std::string generate_private_key_json(int layer, const std::vector<std::string>& attrs);

    // 策略转换
    // layer: 层级
    // policy: 原始策略表达式
    std::string convert_policy(int layer, const std::string& policy);

    // 配置属性映射
    // layer: 层级
    // attr_map: 属性名到ID的映射
    void set_attribute_map(int layer, const std::unordered_map<std::string, int>& attr_map);

    // 获取配对对象（用于客户端序列化）
    pairing_t* get_pairing() { return &pairing_; }

private:
    // 内部初始化辅助
    void cleanup();
    void init_converters();

    pairing_t pairing_;
    bool initialized_;

    // Layer 1 keys
    CP_ABE_PK mpk1_;
    CP_ABE_MSK msk1_;
    int max_attrs_;

    // Layer 2 keys (optional, for hierarchical ABE)
    bool has_layer2_;
    CP_ABE_PK mpk2_;
    CP_ABE_MSK msk2_;

    // 属性映射
    std::unordered_map<std::string, int> attr_map1_;
    std::unordered_map<std::string, int> attr_map2_;

    // 策略转换器
    ExpressionParser parser_;
    std::unique_ptr<AccessConverter> converter1_;
    std::unique_ptr<AccessConverter> converter2_;
};

// 帮助函数：从JSON字符串加载公钥
CP_ABE_PK json_to_cpabe_pk(const std::string& json_str, pairing_t pairing);

// 帮助函数：将私钥转为JSON字符串
std::string cpabe_sk_to_json_str(CP_ABE_SK& sk);

// 帮助函数：从JSON字符串加载私钥
CP_ABE_SK json_to_cpabe_sk(const std::string& json_str, pairing_t pairing);

}  // namespace abe

#endif  // ABE_AUTHORITY_H
