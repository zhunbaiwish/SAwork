#include "sm9_ibe.h"
#include <gmssl/sm9.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <iostream>
#include <cerrno>
#include <vector>
SM9_IBE::SM9_IBE() : master_key(nullptr), master_pub(nullptr), sm9_ctx(nullptr) {}
SM9_IBE::~SM9_IBE() {
    if (master_key) { free(master_key); master_key = nullptr; }
    if (master_pub) { free(master_pub); master_pub = nullptr; }
}

bool SM9_IBE::generate_master_key(const std::string& master_key_file) {
    SM9_ENC_MASTER_KEY msk;
    if (!sm9_enc_master_key_generate(&msk)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;

    // first call to get required length
    if (!sm9_enc_master_key_to_der(&msk, nullptr, &derlen)) return false;
    if (derlen == 0) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    // i2d-style: use a temporary pointer because function increments *pp
    {
        uint8_t *p = der;
        if (!sm9_enc_master_key_to_der(&msk, &p, &derlen)) { free(der); return false; }
    }

    //std::cerr << "DEBUG: der ptr=" << static_cast<const void*>(der) << " derlen=" << derlen << "\n";
    //std::cout<<"Serialized SM9 master key to DER format, size="<<derlen<<"\n";
    bool ok = write_file(master_key_file, der, derlen);
    free(der);
    //std::cout<<"Loading master key into memory.\n";
    if (!ok) return false;
    // keep in-memory copy
    if (master_key) { free(master_key); master_key = nullptr; }
    SM9_ENC_MASTER_KEY* m = (SM9_ENC_MASTER_KEY*)malloc(sizeof(SM9_ENC_MASTER_KEY));
    if (!m) return false;
    memcpy(m, &msk, sizeof(*m));
    master_key = m;
    return true;
}

bool SM9_IBE::save_master_key(const std::string& master_key_file) {
    if (!master_key) return false;
    SM9_ENC_MASTER_KEY *m = (SM9_ENC_MASTER_KEY*)master_key;
    uint8_t *der = nullptr;
    size_t derlen = 0;
    // two-step serialization
    if (!sm9_enc_master_key_to_der(m, nullptr, &derlen)) return false;
    if (derlen == 0) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    if (!sm9_enc_master_key_to_der(m, &der, &derlen)) { free(der); return false; }

    bool ok = write_file(master_key_file, der, derlen);
    free(der);
    return ok;
}

bool SM9_IBE::load_master_key(const std::string& master_key_file) {
    std::vector<uint8_t> buf;
    if (!read_file(master_key_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_ENC_MASTER_KEY tmp;
    if (!sm9_enc_master_key_from_der(&tmp, &p, &len)) return false;
    if (master_key) { free(master_key); master_key = nullptr; }
    SM9_ENC_MASTER_KEY* m = (SM9_ENC_MASTER_KEY*)malloc(sizeof(SM9_ENC_MASTER_KEY));
    if (!m) return false;
    memcpy(m, &tmp, sizeof(*m));
    master_key = m;
    return true;
}

bool SM9_IBE::generate_user_private_key(const std::string& user_id, 
                                        const std::string& user_key_file) {
    if (!master_key) return false;
    SM9_ENC_MASTER_KEY *m = (SM9_ENC_MASTER_KEY*)master_key;
    SM9_ENC_KEY key;
    if (!sm9_enc_master_key_extract_key(m, user_id.c_str(), user_id.size(), &key)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    // two-step for key DER
    if (!sm9_enc_key_to_der(&key, nullptr, &derlen)) return false;
    if (derlen == 0) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        //临时指针p,会随着sm9_enc_key_to_der的调用而移动,所以传入&p,而不是der，以保证写入der的起始位置不变
        if (!sm9_enc_key_to_der(&key, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(user_key_file, der, derlen);
    free(der);
    return ok;
}

bool SM9_IBE::save_master_public(const std::string& pub_file) {
    if (!master_key) return false;
    SM9_ENC_MASTER_KEY *m = (SM9_ENC_MASTER_KEY*)master_key;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_enc_master_public_key_to_der(m, nullptr, &derlen)) return false;
    if (derlen == 0) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_enc_master_public_key_to_der(m, &p, &derlen)) { free(der); return false; }
    }

    bool ok = write_file(pub_file, der, derlen);

    // parse DER back into an in-memory public-only master struct (so encrypt can use it)
    if (ok) {
        const uint8_t *pp = der;
        size_t plen = derlen;
        SM9_ENC_MASTER_KEY *mpk = (SM9_ENC_MASTER_KEY*)malloc(sizeof(SM9_ENC_MASTER_KEY));
        if (!mpk) { ok = false; }
        else {
            if (!sm9_enc_master_public_key_from_der(mpk, &pp, &plen)) {
                free(mpk);
                ok = false;
            } else {
                if (master_pub) { free(master_pub); master_pub = nullptr; }
                master_pub = mpk;
            }
        }
    }

    free(der);
    return ok;
}

bool SM9_IBE::load_master_public(const std::string& pub_file) {
    std::vector<uint8_t> buf;
    if (!read_file(pub_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_ENC_MASTER_KEY *mpk = (SM9_ENC_MASTER_KEY*)malloc(sizeof(SM9_ENC_MASTER_KEY));
    if (!mpk) return false;
    if (!sm9_enc_master_public_key_from_der(mpk, &p, &len)) { free(mpk); return false; }
    if (master_pub) { free(master_pub); master_pub = nullptr; }
    master_pub = mpk;
    return true;
}

// 从内存中的 DER 缓冲区加载 MPK（用于从网络接收或内存传递的情形）
bool SM9_IBE::load_master_public_der(const std::vector<uint8_t>& der) {
    if (der.empty()) return false;
    const uint8_t *p = der.data();
    size_t len = der.size();
    SM9_ENC_MASTER_KEY *mpk = (SM9_ENC_MASTER_KEY*)malloc(sizeof(SM9_ENC_MASTER_KEY));
    if (!mpk) return false;
    if (!sm9_enc_master_public_key_from_der(mpk, &p, &len)) { free(mpk); return false; }
    if (master_pub) { free(master_pub); master_pub = nullptr; }
    master_pub = mpk;
    return true;
}

bool SM9_IBE::encrypt(const std::string& user_id, 
                      const std::vector<unsigned char>& plaintext,
                      std::vector<unsigned char>& ciphertext) {
    // choose MPK: prefer loaded master_pub; fall back to full master_key if available
    SM9_ENC_MASTER_KEY *mpk = nullptr;
    if (master_pub) mpk = (SM9_ENC_MASTER_KEY*)master_pub;
    else if (master_key) mpk = (SM9_ENC_MASTER_KEY*)master_key;
    else return false;

    if (plaintext.size() > SM9_MAX_PLAINTEXT_SIZE) return false;

    std::vector<uint8_t> outbuf(SM9_MAX_CIPHERTEXT_SIZE);
    size_t outlen = outbuf.size();
    int ret = sm9_encrypt(mpk, user_id.c_str(), user_id.size(),
                          plaintext.data(), plaintext.size(),
                          outbuf.data(), &outlen);
    if (ret != 1) return false;
    ciphertext.assign(outbuf.begin(), outbuf.begin() + outlen);
    return true;
}

bool SM9_IBE::decrypt(const std::string& user_id,
                      const std::string& user_key_file,
                      const std::vector<unsigned char>& ciphertext,
                      std::vector<unsigned char>& plaintext) {
    // load user's private key from file
    std::vector<uint8_t> buf;
    if (!read_file(user_key_file, buf)) return false;
    const uint8_t *p = buf.data();
    size_t len = buf.size();
    SM9_ENC_KEY key;
    if (!sm9_enc_key_from_der(&key, &p, &len)) return false;

    std::vector<uint8_t> outbuf(SM9_MAX_PLAINTEXT_SIZE);
    size_t outlen = outbuf.size();
    int ret = sm9_decrypt(&key, user_id.c_str(), user_id.size(),
                          ciphertext.data(), ciphertext.size(),
                          outbuf.data(), &outlen);
    if (ret != 1) return false;
    plaintext.assign(outbuf.begin(), outbuf.begin() + outlen);
    return true;
}

// Export user's private key as DER into out_der (PKG -> 网络发送)
bool SM9_IBE::export_user_private_key_der(const std::string& user_id, std::vector<uint8_t>& out_der) {
    if (!master_key) return false;
    SM9_ENC_MASTER_KEY *m = (SM9_ENC_MASTER_KEY*)master_key;
    SM9_ENC_KEY key;
    if (!sm9_enc_master_key_extract_key(m, user_id.c_str(), user_id.size(), &key)) return false;

    uint8_t *der = nullptr;
    size_t derlen = 0;
    if (!sm9_enc_key_to_der(&key, nullptr, &derlen)) return false;
    if (derlen == 0) return false;
    der = (uint8_t*)malloc(derlen);
    if (!der) return false;
    {
        uint8_t *p = der;
        if (!sm9_enc_key_to_der(&key, &p, &derlen)) { free(der); return false; }
    }
    out_der.assign(der, der + derlen);
    free(der);
    return true;
}

// Decrypt using a user private key provided as DER (模拟接收方收到从网络来的私钥)
bool SM9_IBE::decrypt_with_user_private_der(const std::vector<uint8_t>& user_priv_der,
                                            const std::string& user_id,
                                            const std::vector<unsigned char>& ciphertext,
                                            std::vector<unsigned char>& plaintext) {
    if (user_priv_der.empty()) return false;
    const uint8_t *p = user_priv_der.data();
    size_t len = user_priv_der.size();
    SM9_ENC_KEY key;
    if (!sm9_enc_key_from_der(&key, &p, &len)) return false;

    std::vector<uint8_t> outbuf(SM9_MAX_PLAINTEXT_SIZE);
    size_t outlen = outbuf.size();
    int ret = sm9_decrypt(&key, user_id.c_str(), user_id.size(),
                          ciphertext.data(), ciphertext.size(),
                          outbuf.data(), &outlen);
    if (ret != 1) return false;
    plaintext.assign(outbuf.begin(), outbuf.begin() + outlen);
    return true;
}