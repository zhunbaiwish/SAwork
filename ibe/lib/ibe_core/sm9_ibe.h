#ifndef SM9_IBE_H
#define SM9_IBE_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include "io.h"
class SM9_IBE {
public:
    SM9_IBE();
    ~SM9_IBE();

    // MSK 生成（PKG 使用，MSK 本地保存）
    bool generate_master_key(const std::string& master_key_file = "sm9_master.key");
    
    // 导出/保存 MPK（public only）供加密方使用
    bool save_master_public(const std::string& pub_file = "sm9_master.pub");
    bool load_master_public(const std::string& pub_file = "sm9_master.pub");
    // 从 DER 缓冲区加载 MPK（内存中的 DER），用于网络或内存传输场景
    bool load_master_public_der(const std::vector<uint8_t>& der);

    // 用户私钥生成 (PKG 使用，生成后下发给用户)
    bool generate_user_private_key(const std::string& user_id, 
                                  const std::string& user_key_file);

    // 导出用户私钥为 DER（二进制），用于“网络发送”
    bool export_user_private_key_der(const std::string& user_id, std::vector<uint8_t>& out_der);
    
    // 加密（使用 MPK，而非 MSK）
    bool encrypt(const std::string& user_id, 
                 const std::vector<unsigned char>& plaintext,
                 std::vector<unsigned char>& ciphertext);
    bool decrypt(const std::string& user_id,
                      const std::string& user_key_file,
                      const std::vector<unsigned char>& ciphertext,
                      std::vector<unsigned char>& plaintext);
    // 解密（使用从网络收到的用户私钥 DER）
    bool decrypt_with_user_private_der(const std::vector<uint8_t>& user_priv_der,
                                       const std::string& user_id,
                                       const std::vector<unsigned char>& ciphertext,
                                       std::vector<unsigned char>& plaintext);
    // 兼容：从文件加载/保存 master key
    bool load_master_key(const std::string& master_key_file);
    bool save_master_key(const std::string& master_key_file);
    
private:
    void* master_key;  // 指向 SM9_ENC_MASTER_KEY （cast 用）
    void* master_pub;  // 指向 SM9_ENC_MASTER_KEY (public-only deserialized)
    void* sm9_ctx;     // 备用（未使用）
};

#endif