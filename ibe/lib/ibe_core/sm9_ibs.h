// sm9_ibs.h
#ifndef SM9_IBS_H
#define SM9_IBS_H
#include <gmssl/sm9.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <cerrno>
#include "io.h"
class SM9_IBS {
public:
    SM9_IBS();
    ~SM9_IBS();

    // Master key generation (PKG usage)
    bool generate_master_key(const std::string &master_key_file = "sm9_ibs_master.key");

    // Export/Import master public key for verifier
    bool save_master_public(const std::string &pub_file = "sm9_ibs_master.pub");
    bool load_master_public(const std::string &pub_file = "sm9_ibs_master.pub");

    // User private key generation (PKG usage)
    bool generate_user_private_key(const std::string &user_id, const std::string &user_key_file);

    // Export user private key DER for transmission
    bool export_user_private_key_der(const std::string &user_id, std::vector<uint8_t> &out_der);

    // Sign/Verify functions
    bool sign(const std::string &user_key_file, const std::vector<unsigned char> &message, std::vector<uint8_t> &signature);
    bool sign_with_der(const std::vector<uint8_t> &user_priv_der, const std::vector<unsigned char> &message, std::vector<uint8_t> &signature);
    bool verify(const std::string &user_id, const std::vector<unsigned char> &message, const std::vector<uint8_t> &signature);

    // Load/Save master private key (MSK)
    bool load_master_key(const std::string &master_key_file);
    bool save_master_key(const std::string &master_key_file);

private:
    void *master_key_; // pointer to SM9_SIGN_MASTER_KEY
    void *master_pub_; // pointer to SM9_SIGN_MASTER_KEY (public only)

    void print_error(const std::string &where);
};

#endif // SM9_IBS_H