// IBE gRPC Demo - Client
// This demo shows how to use IBE via gRPC
// The client connects to a remote PKG service for key management

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <grpcpp/grpcpp.h>
#include "ibe.grpc.pb.h"
#include "sm9_ibe.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using ibe::IbeService;
using ibe::MasterPub;
using ibe::UserId;
using ibe::UserPriv;
using google::protobuf::Empty;

// gRPC client wrapper
class GrpcIbeClient {
public:
    GrpcIbeClient(std::shared_ptr<Channel> channel)
        : stub_(IbeService::NewStub(channel)) {}

    bool fetch_ibe_master_pub(std::vector<uint8_t>& out_der) {
        Empty req;
        MasterPub resp;
        ClientContext ctx;
        Status status = stub_->GetIBEMasterPublic(&ctx, req, &resp);
        if (!status.ok()) {
            std::cerr << "[Client] GetIBEMasterPublic failed: " << status.error_message() << std::endl;
            return false;
        }
        const std::string& s = resp.der();
        out_der.assign((const uint8_t*)s.data(), (const uint8_t*)s.data() + s.size());
        return true;
    }

    bool fetch_ibe_user_priv(const std::string& user_id, std::vector<uint8_t>& out_der) {
        UserId req;
        req.set_id(user_id);
        UserPriv resp;
        ClientContext ctx;
        Status status = stub_->GetIBEUserPrivateKey(&ctx, req, &resp);
        if (!status.ok()) {
            std::cerr << "[Client] GetIBEUserPrivateKey failed: " << status.error_message() << std::endl;
            return false;
        }
        const std::string& s = resp.der();
        out_der.assign((const uint8_t*)s.data(), (const uint8_t*)s.data() + s.size());
        return true;
    }

private:
    std::unique_ptr<IbeService::Stub> stub_;
};

int main(int argc, char** argv) {
    std::string server_address = "localhost:50051";

    std::cout << "=== IBE gRPC Demo - Client ===" << std::endl;
    std::cout << "[Client] Connecting to server at " << server_address << std::endl;

    // Create gRPC channel
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    GrpcIbeClient client(channel);

    // Get master public key from server
    std::cout << "[Client] Fetching master public key..." << std::endl;
    std::vector<uint8_t> mpk_der;
    if (!client.fetch_ibe_master_pub(mpk_der)) {
        std::cerr << "[Client] Failed to get master public key" << std::endl;
        return 1;
    }
    std::cout << "[Client] Got master public key, size: " << mpk_der.size() << " bytes" << std::endl;

    // Load master public key
    SM9_IBE sender;
    if (!sender.load_master_public_der(mpk_der)) {
        std::cerr << "[Client] Failed to load master public key" << std::endl;
        return 1;
    }

    // Encrypt message
    std::string user_id = "user@example.com";
    std::string plaintext = "Hello, SM9 IBE via gRPC!";
    std::cout << "[Client] Encrypting message for: " << user_id << std::endl;
    std::vector<unsigned char> pt(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> ciphertext;

    if (!sender.encrypt(user_id, pt, ciphertext)) {
        std::cerr << "[Client] Encryption failed" << std::endl;
        return 1;
    }
    std::cout << "[Client] Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;

    // Get user private key from server
    std::cout << "[Client] Fetching user private key..." << std::endl;
    std::vector<uint8_t> user_priv_der;
    if (!client.fetch_ibe_user_priv(user_id, user_priv_der)) {
        std::cerr << "[Client] Failed to get user private key" << std::endl;
        return 1;
    }
    std::cout << "[Client] Got user private key, size: " << user_priv_der.size() << " bytes" << std::endl;

    // Decrypt message
    std::cout << "[Client] Decrypting message..." << std::endl;
    std::vector<unsigned char> decrypted;
    SM9_IBE receiver;
    if (!receiver.decrypt_with_user_private_der(user_priv_der, user_id, ciphertext, decrypted)) {
        std::cerr << "[Client] Decryption failed" << std::endl;
        return 1;
    }

    std::string recovered(decrypted.begin(), decrypted.end());
    std::cout << "[Client] Decrypted: " << recovered << std::endl;

    if (recovered == plaintext) {
        std::cout << "[Client] SUCCESS!" << std::endl;
    } else {
        std::cout << "[Client] FAILED! Messages don't match." << std::endl;
    }

    std::cout << "\n[Client] Demo completed." << std::endl;
    return 0;
}
