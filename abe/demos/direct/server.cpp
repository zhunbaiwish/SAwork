// ABE Direct Interface Demo - Server (PKG)
// This demo shows how to use ABE core API directly without gRPC
// The server holds master keys and issues private keys, saves to bin files

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include "abe/authority.h"
#include "CPABE_serialize.h"

int main() {
    std::cout << "=== ABE Direct Interface Demo - Server ===" << std::endl;

    // Create Attribute Authority instance
    auto aa = std::make_unique<abe::AttributeAuthority>();

    // Attribute mapping
    std::unordered_map<std::string, int> attr_map = {
        {"role:admin", 1}, {"clearance:high", 2}, {"dept:finance", 3},
        {"role:user", 4}, {"clearance:low", 5}, {"dept:hr", 6},
        {"team:alpha", 7}, {"team:beta", 8}, {"project:X", 9}, {"project:Y", 10}
    };
    aa->set_attribute_map(1, attr_map);
    aa->set_attribute_map(2, attr_map);

    // Initialize AA with pairing parameters
    std::cout << "[Server] Initializing AA with a.param..." << std::endl;
    if (!aa->initialize("a.param", 10)) {
        std::cerr << "[Server] Failed to initialize AA" << std::endl;
        return 1;
    }
    std::cout << "[Server] AA initialized successfully" << std::endl;

    // Get pairing for serialization
    pairing_t* pairing = aa->get_pairing();

    // ========== Layer 1 Keys ==========
    std::cout << "[Server] Processing Layer 1 keys..." << std::endl;

    // Get Layer 1 public key JSON and save to bin
    std::string pk1_json = aa->get_public_key_json(1);
    CP_ABE_PK pk1 = abe::json_to_cpabe_pk(pk1_json, *pairing);
    serializeToFile(pk1, "abe_public_key_1.bin");
    std::cout << "[Server] Layer 1 public key saved to abe_public_key_1.bin" << std::endl;

    // Generate and save Layer 1 private key
    std::vector<std::string> attrs1 = {"role:admin", "clearance:high"};
    std::string sk1_json = aa->generate_private_key_json(1, attrs1);
    CP_ABE_SK sk1 = abe::json_to_cpabe_sk(sk1_json, *pairing);
    serializeToFile(sk1, "abe_secret_key_1.bin");
    std::cout << "[Server] Layer 1 private key saved to abe_secret_key_1.bin (attrs: ";
    for (const auto& attr : attrs1) std::cout << attr << " ";
    std::cout << ")" << std::endl;

    // ========== Layer 2 Keys ==========
    std::cout << "[Server] Processing Layer 2 keys..." << std::endl;

    // Get Layer 2 public key JSON and save to bin
    std::string pk2_json = aa->get_public_key_json(2);
    CP_ABE_PK pk2 = abe::json_to_cpabe_pk(pk2_json, *pairing);
    serializeToFile(pk2, "abe_public_key_2.bin");
    std::cout << "[Server] Layer 2 public key saved to abe_public_key_2.bin" << std::endl;

    // Generate and save Layer 2 private key
    std::vector<std::string> attrs2 = {"team:alpha", "project:X"};
    std::string sk2_json = aa->generate_private_key_json(2, attrs2);
    CP_ABE_SK sk2 = abe::json_to_cpabe_sk(sk2_json, *pairing);
    serializeToFile(sk2, "abe_secret_key_2.bin");
    std::cout << "[Server] Layer 2 private key saved to abe_secret_key_2.bin (attrs: ";
    for (const auto& attr : attrs2) std::cout << attr << " ";
    std::cout << ")" << std::endl;

    // ========== Policy Conversion ==========
    std::cout << "\n[Server] Policy conversion test..." << std::endl;
    std::string policy1 = "(role:admin AND clearance:high) OR (dept:finance AND role:user)";
    std::string converted1 = aa->convert_policy(1, policy1);
    std::cout << "[Server] Policy 1: " << policy1 << std::endl;
    std::cout << "[Server] Converted: " << converted1 << std::endl;

    std::string policy2 = "((team:alpha AND project:X) OR (team:beta AND project:Y) OR dept:hr)";
    std::string converted2 = aa->convert_policy(2, policy2);
    std::cout << "[Server] Policy 2: " << policy2 << std::endl;
    std::cout << "[Server] Converted: " << converted2 << std::endl;

    std::cout << "\n[Server] Server initialization complete." << std::endl;
    std::cout << "[Server] Keys saved to bin files for client demo." << std::endl;

    return 0;
}
