// ABE Direct Interface Demo - Client
// This demo shows how to use ABE core API directly for encryption/decryption
// The client loads keys from files (simulating network transfer)

#include <iostream>
#include <memory>
#include <string>
#include <cstring>
#include "CPABE.h"
#include "CPABE_serialize.h"

int main() {
    std::cout << "=== ABE Direct Interface Demo - Client ===" << std::endl;

    // Initialize pairing
    pairing_t pairing;
    init_pairing(pairing, "a.param");
    std::cout << "[Client] Pairing initialized" << std::endl;

    // Load public keys and private keys from files
    // (In production, these would be received via network)

    // Load Layer 1 public key
    std::cout << "[Client] Loading Layer 1 public key..." << std::endl;
    CP_ABE_PK pk1;
    init_CP_ABE_PK(pk1, 10);
    deSerializeFromFile(pk1, "abe_public_key_1.bin", pairing);

    // Load Layer 1 private key
    std::cout << "[Client] Loading Layer 1 private key..." << std::endl;
    CP_ABE_SK sk1;
    init_CP_ABE_SK(sk1, 10);
    deSerializeFromFile(sk1, "abe_secret_key_1.bin", pairing);

    // Load Layer 2 public key
    std::cout << "[Client] Loading Layer 2 public key..." << std::endl;
    CP_ABE_PK pk2;
    init_CP_ABE_PK(pk2, 10);
    deSerializeFromFile(pk2, "abe_public_key_2.bin", pairing);

    // Load Layer 2 private key
    std::cout << "[Client] Loading Layer 2 private key..." << std::endl;
    CP_ABE_SK sk2;
    init_CP_ABE_SK(sk2, 10);
    deSerializeFromFile(sk2, "abe_secret_key_2.bin", pairing);

    std::cout << "[Client] All keys loaded successfully" << std::endl;

    // ==== Layer 1 Encrypt/Decrypt Test ====
    std::cout << "\n--- Layer 1 Test ---" << std::endl;

    // Access policy: role:admin, clearance:high
    int Access1[] = {2,1,1,2,2,2,-1,-2,2,2,-3,-4,0};
    std::string test_plain = "HelloABE123456789012345678901234";
    unsigned char plain_buf[32];
    memcpy(plain_buf, test_plain.data(), 32);
    std::cout << "[Client] Original text: " << plain_buf << std::endl;

    // Encrypt
    CT ct1;
    cpabe_Encrypt(Access1, plain_buf, ct1, pk1, pairing);
    unsigned char ct1_buf[1024*1024];
    int ct1_len = cpabe_SerializeCT(ct1, ct1_buf);
    std::cout << "[Client] Encrypted, ciphertext length: " << ct1_len << std::endl;

    // Deserialize for decryption
    CT dec_ct1;
    cpabe_DeserializeCT(ct1_buf, ct1_len, dec_ct1, pairing);

    // Decrypt
    unsigned char* dec_buf = new unsigned char[32]();
    cpabe_Decrypt(Access1, pairing, dec_ct1, sk1, dec_buf);

    std::string dec_str(reinterpret_cast<char*>(dec_buf), 32);
    std::cout << "[Client] Decrypted text: " << dec_str << std::endl;

    if (dec_str == test_plain) {
        std::cout << "[Client] Layer 1 SUCCESS!" << std::endl;
    } else {
        std::cout << "[Client] Layer 1 FAILED!" << std::endl;
    }
    delete[] dec_buf;

    // ==== Layer 2 Encrypt/Decrypt Test ====
    std::cout << "\n--- Layer 2 Test ---" << std::endl;

    // Access policy: team:alpha, project:X
    int Access2[] = {3,1,1,2,-6,2,2,-7,-9,2,2,-8,-10,0};
    std::string test_plain2 = "Layer2SecretKey9876543210abcdef";
    unsigned char plain_buf2[32];
    memcpy(plain_buf2, test_plain2.data(), 32);
    std::cout << "[Client] Original text: " << plain_buf2 << std::endl;

    // Encrypt
    CT ct2;
    cpabe_Encrypt(Access2, plain_buf2, ct2, pk2, pairing);
    unsigned char ct2_buf[1024*1024];
    int ct2_len = cpabe_SerializeCT(ct2, ct2_buf);
    std::cout << "[Client] Encrypted, ciphertext length: " << ct2_len << std::endl;

    // Deserialize for decryption
    CT dec_ct2;
    cpabe_DeserializeCT(ct2_buf, ct2_len, dec_ct2, pairing);

    // Decrypt
    unsigned char* dec_buf2 = new unsigned char[32]();
    cpabe_Decrypt(Access2, pairing, dec_ct2, sk2, dec_buf2);

    std::string dec_str2(reinterpret_cast<char*>(dec_buf2), test_plain2.size());
    std::cout << "[Client] Decrypted text: " << dec_str2 << std::endl;

    if (dec_str2 == test_plain2) {
        std::cout << "[Client] Layer 2 SUCCESS!" << std::endl;
    } else {
        std::cout << "[Client] Layer 2 FAILED!" << std::endl;
    }
    delete[] dec_buf2;

    std::cout << "\n[Client] All tests completed." << std::endl;
    return 0;
}
