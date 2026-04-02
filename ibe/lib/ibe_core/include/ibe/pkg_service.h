#ifndef IBE_PKG_SERVICE_H
#define IBE_PKG_SERVICE_H

#include <string>
#include <vector>
#include <memory>

// Forward declarations from existing headers
class SM9_IBE;
class SM9_IBS;

namespace ibe {

// PKG (Private Key Generator) 服务类 - 封装IBE/IBS核心业务逻辑
class PkgService {
public:
    PkgService();
    ~PkgService();

    // 初始化（生成或加载主密钥）
    // master_key_file: 主密钥文件路径
    // master_pub_file: 公钥文件路径
    // is_ibe: true=IBE, false=IBS
    bool initialize(const std::string& master_key_file,
                    const std::string& master_pub_file,
                    bool is_ibe = true);

    // 获取主公钥（DER格式，用于网络传输）
    std::vector<uint8_t> get_master_public_der();

    // 生成用户私钥（DER格式，用于网络传输）
    // user_id: 用户身份标识
    std::vector<uint8_t> generate_user_private_key_der(const std::string& user_id);

    // 保存主公钥到文件
    bool save_master_public(const std::string& pub_file);

    // 加载主公钥
    bool load_master_public(const std::string& pub_file);

    // 加载主公钥（从DER缓冲区）
    bool load_master_public_der(const std::vector<uint8_t>& der);

private:
    std::unique_ptr<SM9_IBE> ibe_pkg_;
    std::unique_ptr<SM9_IBS> ibs_pkg_;
    bool initialized_;
};

// IBE加密辅助函数
bool ibe_encrypt(SM9_IBE& ibe,
                  const std::string& user_id,
                  const std::vector<unsigned char>& plaintext,
                  std::vector<unsigned char>& ciphertext);

// IBE解密辅助函数（使用DER私钥）
bool ibe_decrypt_with_der(SM9_IBE& ibe,
                          const std::vector<uint8_t>& user_priv_der,
                          const std::string& user_id,
                          const std::vector<unsigned char>& ciphertext,
                          std::vector<unsigned char>& plaintext);

// IBS签名辅助函数（使用DER私钥）
bool ibs_sign_with_der(SM9_IBS& ibs,
                       const std::vector<uint8_t>& user_priv_der,
                       const std::vector<unsigned char>& message,
                       std::vector<unsigned char>& signature);

}  // namespace ibe

#endif  // IBE_PKG_SERVICE_H
