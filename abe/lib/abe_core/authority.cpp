#include "abe/authority.h"
#include <iostream>
#include <cstring>

namespace abe {

AttributeAuthority::AttributeAuthority()
    : initialized_(false), has_layer2_(false), max_attrs_(0) {
    // 默认属性映射
    attr_map1_ = {
        {"role:admin", 1},
        {"clearance:high", 2},
        {"dept:finance", 3},
        {"role:user", 4},
        {"clearance:low", 5},
        {"dept:hr", 6},
        {"team:alpha", 7},
        {"team:beta", 8},
        {"project:X", 9},
        {"project:Y", 10}
    };
    attr_map2_ = attr_map1_;  // 第二层默认与第一层相同

    // 初始化转换器
    converter1_ = std::make_unique<AccessConverter>(attr_map1_);
    converter2_ = std::make_unique<AccessConverter>(attr_map2_);
}

AttributeAuthority::~AttributeAuthority() {
    cleanup();
}

void AttributeAuthority::cleanup() {
    initialized_ = false;
}

void AttributeAuthority::init_converters() {
    converter1_ = std::make_unique<AccessConverter>(attr_map1_);
    converter2_ = std::make_unique<AccessConverter>(attr_map2_);
}

bool AttributeAuthority::initialize(const std::string& param_file, int max_attrs) {
    if (initialized_) {
        std::cerr << "[ABE Authority] Already initialized\n";
        return false;
    }

    max_attrs_ = max_attrs;

    // 初始化第一层密钥
    init_CP_ABE_PK(mpk1_, max_attrs_);

    std::cout << "[ABE Authority] Initializing pairing from: " << param_file << std::endl;
    if (init_pairing(pairing_, param_file.c_str()) != 0) {
        std::cerr << "[ABE Authority] Failed to initialize pairing\n";
        return false;
    }

    std::cout << "[ABE Authority] Generating Layer 1 master keys...\n";
    cpabe_Setup(mpk1_, msk1_, pairing_);

    // 初始化第二层密钥（可选层次结构）
    has_layer2_ = true;
    init_CP_ABE_PK(mpk2_, max_attrs_);
    std::cout << "[ABE Authority] Generating Layer 2 master keys...\n";
    cpabe_Setup(mpk2_, msk2_, pairing_);

    initialized_ = true;
    std::cout << "[ABE Authority] Initialization complete\n";
    return true;
}

std::string AttributeAuthority::get_public_key_json(int layer) {
    if (!initialized_) {
        return "{}";
    }

    CP_ABE_PK* pk = nullptr;
    if (layer == 1) {
        pk = &mpk1_;
    } else if (layer == 2 && has_layer2_) {
        pk = &mpk2_;
    } else {
        return "{}";
    }

    json j = cpabe_pk_to_json(*pk);
    return j.dump();
}

std::string AttributeAuthority::generate_private_key_json(int layer, const std::vector<std::string>& attrs) {
    if (!initialized_) {
        return "{}";
    }

    CP_ABE_SK sk;
    CP_ABE_PK* pk = nullptr;
    CP_ABE_MSK* msk = nullptr;
    std::unordered_map<std::string, int>* attr_map = nullptr;

    if (layer == 1) {
        pk = &mpk1_;
        msk = &msk1_;
        attr_map = &attr_map1_;
    } else if (layer == 2 && has_layer2_) {
        pk = &mpk2_;
        msk = &msk2_;
        attr_map = &attr_map2_;
    } else {
        return "{}";
    }

    // 转换属性名为ID
    std::vector<int> attr_ids;
    for (const auto& attr : attrs) {
        if (!attr.empty()) {
            auto it = attr_map->find(attr);
            if (it != attr_map->end()) {
                attr_ids.push_back(it->second);
            }
        }
    }
    attr_ids.push_back(0);  // 结束标记

    init_CP_ABE_SK(sk, max_attrs_);
    cpabe_Keygen(sk, attr_ids.data(), *pk, *msk, pairing_);

    json j = cpabe_sk_to_json(sk);
    std::cout << "[ABE Authority] Generated Layer " << layer << " private key for attributes: ";
    for (const auto& attr : attrs) std::cout << attr << " ";
    std::cout << std::endl;

    return j.dump();
}

std::string AttributeAuthority::convert_policy(int layer, const std::string& policy) {
    AST_Node* root = parser_.parse(policy);
    if (!root) {
        return "";
    }

    std::string result;
    if (layer == 1 && converter1_) {
        auto access_list = converter1_->convert(root);
        result = access_to_string(access_list);
    } else if (layer == 2 && has_layer2_ && converter2_) {
        auto access_list = converter2_->convert(root);
        result = access_to_string(access_list);
    }

    std::cout << "[ABE Authority] Converted Policy (Layer " << layer << "): " << result << std::endl;
    return result;
}

void AttributeAuthority::set_attribute_map(int layer, const std::unordered_map<std::string, int>& attr_map) {
    if (layer == 1) {
        attr_map1_ = attr_map;
        converter1_ = std::make_unique<AccessConverter>(attr_map1_);
    } else if (layer == 2) {
        attr_map2_ = attr_map;
        converter2_ = std::make_unique<AccessConverter>(attr_map2_);
    }
}

// ============ Helper Functions ============

CP_ABE_PK json_to_cpabe_pk(const std::string& json_str, pairing_t pairing) {
    json j = json::parse(json_str);
    return jsonToCPABEPK(j, pairing);
}

std::string cpabe_sk_to_json_str(CP_ABE_SK& sk) {
    return cpabe_sk_to_json(sk).dump();
}

CP_ABE_SK json_to_cpabe_sk(const std::string& json_str, pairing_t pairing) {
    json j = json::parse(json_str);
    return jsonToCPABESK(j, pairing);
}

}  // namespace abe
