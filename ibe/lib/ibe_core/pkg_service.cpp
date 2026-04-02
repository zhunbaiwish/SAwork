#include "ibe/pkg_service.h"
#include "../sm9_ibe.h"
#include "../sm9_ibs.h"
#include <iostream>
#include <cstdio>

namespace ibe {

struct PkgServiceImpl {
    SM9_IBE* ibe_pkg;
    SM9_IBS* ibs_pkg;

    PkgServiceImpl() : ibe_pkg(nullptr), ibs_pkg(nullptr) {}
    ~PkgServiceImpl() {
        delete ibe_pkg;
        delete ibs_pkg;
    }
};

PkgService::PkgService() : initialized_(false) {}

PkgService::~PkgService() {}

bool PkgService::initialize(const std::string& master_key_file,
                            const std::string& master_pub_file,
                            bool is_ibe) {
    // Create IBE PKG
    SM9_IBE* ibe = new SM9_IBE();
    SM9_IBS* ibs = new SM9_IBS();

    // Generate master keys if files don't exist
    if (!ibe->generate_master_key(master_key_file)) {
        std::cerr << "[PkgService] Failed to generate IBE master key\n";
        delete ibe;
        delete ibs;
        return false;
    }
    ibe->save_master_public(master_pub_file);

    if (!ibs->generate_master_key(master_key_file + "_ibs")) {
        std::cerr << "[PkgService] Failed to generate IBS master key\n";
        delete ibe;
        delete ibs;
        return false;
    }
    ibs->save_master_public(master_pub_file + "_ibs");

    ibe_pkg_ = std::unique_ptr<SM9_IBE>(ibe);
    ibs_pkg_ = std::unique_ptr<SM9_IBS>(ibs);
    initialized_ = true;

    std::cout << "[PkgService] Initialized successfully\n";
    return true;
}

std::vector<uint8_t> PkgService::get_master_public_der() {
    std::vector<uint8_t> result;
    if (!initialized_ || !ibe_pkg_) {
        return result;
    }

    // Read from default master public file
    const std::string pub_file = "sm9_ibe_master.pub";
    FILE* fp = fopen(pub_file.c_str(), "rb");
    if (!fp) {
        std::cerr << "[PkgService] Failed to open master public file: " << pub_file << "\n";
        return result;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz > 0) {
        result.resize((size_t)sz);
        fread(result.data(), 1, result.size(), fp);
    }
    fclose(fp);

    return result;
}

std::vector<uint8_t> PkgService::generate_user_private_key_der(const std::string& user_id) {
    std::vector<uint8_t> result;
    if (!initialized_ || !ibe_pkg_) {
        return result;
    }

    if (!ibe_pkg_->export_user_private_key_der(user_id, result)) {
        std::cerr << "[PkgService] Failed to export user private key for: " << user_id << "\n";
        return result;
    }

    std::cout << "[PkgService] Generated private key for user: " << user_id
              << ", size: " << result.size() << " bytes\n";
    return result;
}

bool PkgService::save_master_public(const std::string& pub_file) {
    if (!initialized_ || !ibe_pkg_) {
        return false;
    }
    return ibe_pkg_->save_master_public(pub_file);
}

bool PkgService::load_master_public(const std::string& pub_file) {
    if (!initialized_ || !ibe_pkg_) {
        return false;
    }
    return ibe_pkg_->load_master_public(pub_file);
}

bool PkgService::load_master_public_der(const std::vector<uint8_t>& der) {
    if (!initialized_ || !ibe_pkg_) {
        return false;
    }
    return ibe_pkg_->load_master_public_der(der);
}

// ============ Helper Functions ============

bool ibe_encrypt(SM9_IBE& ibe,
                  const std::string& user_id,
                  const std::vector<unsigned char>& plaintext,
                  std::vector<unsigned char>& ciphertext) {
    return ibe.encrypt(user_id, plaintext, ciphertext);
}

bool ibe_decrypt_with_der(SM9_IBE& ibe,
                          const std::vector<uint8_t>& user_priv_der,
                          const std::string& user_id,
                          const std::vector<unsigned char>& ciphertext,
                          std::vector<unsigned char>& plaintext) {
    return ibe.decrypt_with_user_private_der(user_priv_der, user_id, ciphertext, plaintext);
}

bool ibs_sign_with_der(SM9_IBS& ibs,
                       const std::vector<uint8_t>& user_priv_der,
                       const std::vector<unsigned char>& message,
                       std::vector<unsigned char>& signature) {
    return ibs.sign_with_der(user_priv_der, message, signature);
}

}  // namespace ibe
