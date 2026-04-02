// sm9_ibs.cpp
#include "sm9_ibs.h"
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <cstdio>
#include <cstring>

SM9_IBS::SM9_IBS() : master_key_(nullptr), master_pub_(nullptr) {}
SM9_IBS::~SM9_IBS() {
    if (master_key_) { free(master_key_); master_key_ = nullptr; }
    if (master_pub_) { free(master_pub_); master_pub_ = nullptr; }
}

bool SM9_IBS::generate_master_key(const std::string &master_key_file) {
    SM9_SIGN_MASTER_KEY msk;
    if (!sm9_sign_master_key_generate(&msk)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_sign_master_key_to_der(&msk, nullptr, &derlen)) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_sign_master_key_to_der(&msk, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(master_key_file, der, derlen);
    free(der);
    if (!ok) return false;

    if (master_key_) { free(master_key_); master_key_ = nullptr; }
    SM9_SIGN_MASTER_KEY *m = (SM9_SIGN_MASTER_KEY*)malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!m) return false;
    memcpy(m, &msk, sizeof(*m));
    master_key_ = m;
    return true;
}

bool SM9_IBS::save_master_key(const std::string &master_key_file) {
    if (!master_key_) return false;
    SM9_SIGN_MASTER_KEY *m = (SM9_SIGN_MASTER_KEY*)master_key_;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_sign_master_key_to_der(m, nullptr, &derlen)) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_sign_master_key_to_der(m, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(master_key_file, der, derlen);
    free(der);
    return ok;
}

bool SM9_IBS::load_master_key(const std::string &master_key_file) {
    std::vector<uint8_t> buf;
    if (!read_file(master_key_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_SIGN_MASTER_KEY tmp;
    if (!sm9_sign_master_key_from_der(&tmp, &p, &len)) return false;

    if (master_key_) { free(master_key_); master_key_ = nullptr; }
    SM9_SIGN_MASTER_KEY *m = (SM9_SIGN_MASTER_KEY*)malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!m) return false;
    memcpy(m, &tmp, sizeof(*m));
    master_key_ = m;
    return true;
}

bool SM9_IBS::generate_user_private_key(const std::string &user_id, const std::string &user_key_file) {
    if (!master_key_) return false;
    SM9_SIGN_KEY key;
    if (!sm9_sign_master_key_extract_key((SM9_SIGN_MASTER_KEY*)master_key_, user_id.c_str(), user_id.size(), &key)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_sign_key_to_der(&key, nullptr, &derlen)) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_sign_key_to_der(&key, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(user_key_file, der, derlen);
    free(der);
    return ok;
}

bool SM9_IBS::save_master_public(const std::string &pub_file) {
    if (!master_key_) return false;
    SM9_SIGN_MASTER_KEY *m = (SM9_SIGN_MASTER_KEY*)master_key_;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_sign_master_public_key_to_der(m, nullptr, &derlen)) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_sign_master_public_key_to_der(m, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(pub_file, der, derlen);
    if (ok) {
        const uint8_t *pp = der;
        size_t plen = derlen;
        SM9_SIGN_MASTER_KEY *mpk = (SM9_SIGN_MASTER_KEY*)malloc(sizeof(SM9_SIGN_MASTER_KEY));
        if (!mpk) ok = false;
        else {
            if (!sm9_sign_master_public_key_from_der(mpk, &pp, &plen)) {
                free(mpk);
                ok = false;
            } else {
                if (master_pub_) { free(master_pub_); master_pub_ = nullptr; }
                master_pub_ = mpk;
            }
        }
    }
    free(der);
    return ok;
}

bool SM9_IBS::load_master_public(const std::string &pub_file) {
    std::vector<uint8_t> buf;
    if (!read_file(pub_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_SIGN_MASTER_KEY *mpk = (SM9_SIGN_MASTER_KEY*)malloc(sizeof(SM9_SIGN_MASTER_KEY));
    if (!mpk) return false;
    if (!sm9_sign_master_public_key_from_der(mpk, &p, &len)) { free(mpk); return false; }
    if (master_pub_) { free(master_pub_); master_pub_ = nullptr; }
    master_pub_ = mpk;
    return true;
}

bool SM9_IBS::export_user_private_key_der(const std::string &user_id, std::vector<uint8_t> &out_der) {
    if (!master_key_) return false;
    SM9_SIGN_KEY key;
    if (!sm9_sign_master_key_extract_key((SM9_SIGN_MASTER_KEY*)master_key_, user_id.c_str(), user_id.size(), &key)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_sign_key_to_der(&key, nullptr, &derlen)) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_sign_key_to_der(&key, &p, &derlen)) { free(der); return false; }
    }
    out_der.assign(der, der + derlen);
    free(der);
    return true;
}

bool SM9_IBS::sign(const std::string &user_key_file, const std::vector<unsigned char> &message, std::vector<uint8_t> &signature) {
    std::vector<uint8_t> buf;
    if (!read_file(user_key_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_SIGN_KEY key;
    if (!sm9_sign_key_from_der(&key, &p, &len)) return false;

    SM9_SIGN_CTX ctx;
    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx, message.data(), message.size());
    signature.resize(SM9_SIGNATURE_SIZE);
    size_t siglen = signature.size();
    if (!sm9_sign_finish(&ctx, &key, signature.data(), &siglen)) return false;
    signature.resize(siglen);
    return true;
}

bool SM9_IBS::sign_with_der(const std::vector<uint8_t> &user_priv_der, const std::vector<unsigned char> &message, std::vector<uint8_t> &signature) {
    if (user_priv_der.empty()) return false;
    const uint8_t *p = user_priv_der.data();
    size_t len = user_priv_der.size();
    SM9_SIGN_KEY key;
    if (!sm9_sign_key_from_der(&key, &p, &len)) return false;

    SM9_SIGN_CTX ctx;
    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx, message.data(), message.size());
    signature.resize(SM9_SIGNATURE_SIZE);
    size_t siglen = signature.size();
    if (!sm9_sign_finish(&ctx, &key, signature.data(), &siglen)) return false;
    signature.resize(siglen);
    return true;
}

bool SM9_IBS::verify(const std::string &user_id, const std::vector<unsigned char> &message, const std::vector<uint8_t> &signature) {
    SM9_SIGN_MASTER_KEY *mpk = nullptr;
    if (master_pub_) mpk = (SM9_SIGN_MASTER_KEY*)master_pub_;
    else if (master_key_) mpk = (SM9_SIGN_MASTER_KEY*)master_key_;
    else return false;

    SM9_SIGN_CTX ctx;
    sm9_verify_init(&ctx);
    sm9_verify_update(&ctx, message.data(), message.size());
    int ret = sm9_verify_finish(&ctx, signature.data(), signature.size(), mpk, user_id.c_str(), user_id.size());
    return ret == 1;
}
