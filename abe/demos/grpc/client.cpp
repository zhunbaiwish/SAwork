// ABE gRPC Demo - Client
// This demo shows how to use ABE via gRPC
// The client connects to a remote PKG service for key management

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <cstring>
#include <grpcpp/grpcpp.h>
#include <CPABE.h>
#include <CPABE_serialize.h>
#include "serverInteraction.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using serverInteraction::AttributeAuthorityService;
using serverInteraction::GetABEPublicKeyRequest;
using serverInteraction::GetABEPublicKeyResponse;
using serverInteraction::GetABEPrivateKeyRequest;
using serverInteraction::GetABEPrivateKeyResponse;
using serverInteraction::ConvertPolicyRequest;
using serverInteraction::ConvertPolicyResponse;

std::string server_ip = "localhost";

class GrpcAClient {
public:
    GrpcAClient(std::shared_ptr<Channel> channel)
        : stub_(AttributeAuthorityService::NewStub(channel)) {}

    bool get_public_key(int key_id, std::string& out_pk_json) {
        GetABEPublicKeyRequest request;
        request.set_key_id(key_id);
        GetABEPublicKeyResponse response;
        ClientContext context;
        Status status = stub_->GetABEPublicKey(&context, request, &response);
        if (!status.ok()) {
            std::cerr << "[Client] GetABEPublicKey failed: " << status.error_message() << std::endl;
            return false;
        }
        out_pk_json = response.abe_public_key();
        return true;
    }

    bool get_private_key(int layer, const std::vector<std::string>& attrs, std::string& out_sk_json) {
        GetABEPrivateKeyRequest request;
        request.set_layer(layer);
        for (const auto& attr : attrs) {
            request.add_attrs(attr);
        }
        GetABEPrivateKeyResponse response;
        ClientContext context;
        Status status = stub_->GetABEPrivateKey(&context, request, &response);
        if (!status.ok()) {
            std::cerr << "[Client] GetABEPrivateKey failed: " << status.error_message() << std::endl;
            return false;
        }
        out_sk_json = response.abe_secret_key();
        return true;
    }

    bool convert_policy(int layer, const std::string& policy, std::string& out_converted) {
        ConvertPolicyRequest request;
        request.set_layer(layer);
        request.set_policy(policy);
        ConvertPolicyResponse response;
        ClientContext context;
        Status status = stub_->ConvertPolicy(&context, request, &response);
        if (!status.ok()) {
            std::cerr << "[Client] ConvertPolicy failed: " << status.error_message() << std::endl;
            return false;
        }
        out_converted = response.converted_policy();
        return true;
    }

private:
    std::unique_ptr<AttributeAuthorityService::Stub> stub_;
};

int main(int argc, char** argv) {
    std::string server_address = server_ip + ":50057";

    std::cout << "=== ABE gRPC Demo - Client ===" << std::endl;
    std::cout << "[Client] Connecting to AA_server at " << server_address << "..." << std::endl;

    // Create gRPC channel
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    GrpcAClient client(channel);

    // Initialize pairing
    pairing_t pairing;
    if (init_pairing(pairing, "a.param") != 0) {
        std::cerr << "[Client] Failed to initialize pairing" << std::endl;
        return 1;
    }

    // ========== Request Layer 1 Public Key ==========
    std::cout << "[Client] Requesting PublicKey (key_id=1)..." << std::endl;
    std::string pk1_json;
    if (!client.get_public_key(1, pk1_json)) {
        std::cerr << "[Client] GetPublicKey failed" << std::endl;
        return 1;
    }
    std::cout << "[Client] PublicKey (key_id=1) received" << std::endl;
    serializeToFile(jsonToCPABEPK(json::parse(pk1_json), pairing), "abe_public_key_1.bin");

    // ========== Request Layer 2 Public Key ==========
    std::cout << "[Client] Requesting PublicKey (key_id=2)..." << std::endl;
    std::string pk2_json;
    if (!client.get_public_key(2, pk2_json)) {
        std::cerr << "[Client] GetPublicKey failed" << std::endl;
        return 1;
    }
    std::cout << "[Client] PublicKey (key_id=2) received" << std::endl;
    serializeToFile(jsonToCPABEPK(json::parse(pk2_json), pairing), "abe_public_key_2.bin");

    // ========== Request Layer 1 Private Key ==========
    std::cout << "[Client] Requesting SecretKey for Layer 1 (attrs: role:admin, clearance:high)..." << std::endl;
    std::vector<std::string> attrs1 = {"role:admin", "clearance:high"};
    std::string sk1_json;
    if (!client.get_private_key(1, attrs1, sk1_json)) {
        std::cerr << "[Client] RequestSecretKey failed" << std::endl;
        return 1;
    }
    std::cout << "[Client] SecretKey (Layer 1) received" << std::endl;
    serializeToFile(jsonToCPABESK(json::parse(sk1_json), pairing), "abe_secret_key_1.bin");

    // ========== Request Layer 2 Private Key ==========
    std::cout << "[Client] Requesting SecretKey for Layer 2 (attrs: team:alpha, project:X)..." << std::endl;
    std::vector<std::string> attrs2 = {"team:alpha", "project:X"};
    std::string sk2_json;
    if (!client.get_private_key(2, attrs2, sk2_json)) {
        std::cerr << "[Client] RequestSecretKey (Layer 2) failed" << std::endl;
        return 1;
    }
    std::cout << "[Client] SecretKey (Layer 2) received" << std::endl;
    serializeToFile(jsonToCPABESK(json::parse(sk2_json), pairing), "abe_secret_key_2.bin");

    // ========== Test ConvertPolicy ==========
    std::cout << "[Client] Testing ConvertPolicy (Layer 1)..." << std::endl;
    std::string converted1;
    if (client.convert_policy(1, "(role:admin AND clearance:high) OR (dept:finance AND role:user)", converted1)) {
        std::cout << "[Client] ConvertedPolicy: " << converted1 << std::endl;
    }

    std::cout << "[Client] Testing ConvertPolicy (Layer 2)..." << std::endl;
    std::string converted2;
    if (client.convert_policy(2, "((team:alpha AND project:X) OR (team:beta AND project:Y) OR dept:hr)", converted2)) {
        std::cout << "[Client] ConvertedPolicy: " << converted2 << std::endl;
    }

    // ========== Layer 1 Encrypt/Decrypt Test ==========
    std::cout << "\n[Client] ABE Encrypt/Decrypt Test (Layer 1)..." << std::endl;

    int Access1[] = {2,1,1,2,2,2,-1,-2,2,2,-3,-4,0};
    std::string test_plain1 = "HelloABE123456789012345678901234";
    unsigned char plain_buf1[32];
    memcpy(plain_buf1, test_plain1.data(), 32);
    std::cout << "[Client] Original text: " << plain_buf1 << std::endl;

    // Load keys from files
    CP_ABE_PK pk1;
    init_CP_ABE_PK(pk1, 10);
    deSerializeFromFile(pk1, "abe_public_key_1.bin", pairing);
    CP_ABE_SK sk1;
    init_CP_ABE_SK(sk1, 10);
    deSerializeFromFile(sk1, "abe_secret_key_1.bin", pairing);

    // Encrypt
    CT ct1;
    cpabe_Encrypt(Access1, plain_buf1, ct1, pk1, pairing);
    unsigned char ct1_buf[1024*1024];
    int ct1_len = cpabe_SerializeCT(ct1, ct1_buf);
    std::cout << "[Client] Ciphertext (Layer 1) length: " << ct1_len << std::endl;

    // Deserialize for decryption
    CT dec_ct1;
    cpabe_DeserializeCT(ct1_buf, ct1_len, dec_ct1, pairing);

    // Decrypt
    unsigned char* dec_buf1 = new unsigned char[32]();
    cpabe_Decrypt(Access1, pairing, dec_ct1, sk1, dec_buf1);

    std::string dec_str1(reinterpret_cast<char*>(dec_buf1), 32);
    std::cout << "[Client] Decrypted text: " << dec_str1 << std::endl;
    if (dec_str1 == test_plain1) {
        std::cout << "[Client] Layer 1 ABE Decrypt SUCCESS!" << std::endl;
    } else {
        std::cout << "[Client] Layer 1 ABE Decrypt FAILED!" << std::endl;
    }
    delete[] dec_buf1;

    // ========== Layer 2 Encrypt/Decrypt Test ==========
    std::cout << "\n[Client] ABE Encrypt/Decrypt Test (Layer 2)..." << std::endl;

    int Access2[] = {3,1,1,2,-6,2,2,-7,-9,2,2,-8,-10,0};
    std::string test_plain2 = "Layer2SecretKey9876543210abcdef";
    unsigned char plain_buf2[32];
    memcpy(plain_buf2, test_plain2.data(), 32);
    std::cout << "[Client] Original text: " << plain_buf2 << std::endl;

    // Load keys from files
    CP_ABE_PK pk2;
    init_CP_ABE_PK(pk2, 10);
    deSerializeFromFile(pk2, "abe_public_key_2.bin", pairing);
    CP_ABE_SK sk2;
    init_CP_ABE_SK(sk2, 10);
    deSerializeFromFile(sk2, "abe_secret_key_2.bin", pairing);

    // Encrypt
    CT ct2;
    cpabe_Encrypt(Access2, plain_buf2, ct2, pk2, pairing);
    unsigned char ct2_buf[1024*1024];
    int ct2_len = cpabe_SerializeCT(ct2, ct2_buf);
    std::cout << "[Client] Ciphertext (Layer 2) length: " << ct2_len << std::endl;

    // Deserialize for decryption
    CT dec_ct2;
    cpabe_DeserializeCT(ct2_buf, ct2_len, dec_ct2, pairing);

    // Decrypt
    unsigned char* dec_buf2 = new unsigned char[32]();
    cpabe_Decrypt(Access2, pairing, dec_ct2, sk2, dec_buf2);

    std::string dec_str2(reinterpret_cast<char*>(dec_buf2), test_plain2.size());
    std::cout << "[Client] Decrypted text: " << dec_str2 << std::endl;
    if (dec_str2 == test_plain2) {
        std::cout << "[Client] Layer 2 ABE Decrypt SUCCESS!" << std::endl;
    } else {
        std::cout << "[Client] Layer 2 ABE Decrypt FAILED!" << std::endl;
    }
    delete[] dec_buf2;

    std::cout << "\n[Client] All tests finished." << std::endl;
    return 0;
}
