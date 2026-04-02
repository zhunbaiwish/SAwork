// IBE Direct Interface Demo - Server (PKG)
// This demo shows how to use IBE/IBS core API directly without gRPC
// The server acts as PKG (Private Key Generator)

#include <iostream>
#include <vector>
#include <string>
#include "sm9_ibe.h"
#include "sm9_ibs.h"

int main() {
    std::cout << "=== IBE Direct Interface Demo - Server (PKG) ===" << std::endl;

    const std::string master_pub_file = "sm9_ibe_master.pub";
    const std::string master_key_file = "sm9_ibe_master.key";
    const std::string user_id = "user@example.com";

    // ---------- 1. PKG generates master keys ----------
    std::cout << "[Server] Generating IBE master keys..." << std::endl;
    SM9_IBE ibe_pkg;
    if (!ibe_pkg.generate_master_key(master_key_file)) {
        std::cerr << "[Server] Failed to generate IBE master key" << std::endl;
        return 1;
    }
    if (!ibe_pkg.save_master_public(master_pub_file)) {
        std::cerr << "[Server] Failed to save IBE master public key" << std::endl;
        return 1;
    }
    std::cout << "[Server] IBE master keys saved" << std::endl;

    // ---------- 2. PKG generates user private key ----------
    std::cout << "[Server] Generating user private key for: " << user_id << std::endl;
    std::vector<uint8_t> user_priv_der;
    if (!ibe_pkg.export_user_private_key_der(user_id, user_priv_der)) {
        std::cerr << "[Server] Failed to export user private key" << std::endl;
        return 1;
    }
    std::cout << "[Server] User private key DER size: " << user_priv_der.size() << " bytes" << std::endl;

    // ---------- 3. IBS master key generation ----------
    std::cout << "\n[Server] Generating IBS master keys..." << std::endl;
    SM9_IBS ibs_pkg;
    if (!ibs_pkg.generate_master_key("sm9_ibs_master.key")) {
        std::cerr << "[Server] Failed to generate IBS master key" << std::endl;
        return 1;
    }
    ibs_pkg.save_master_public("sm9_ibs_master.pub");
    std::cout << "[Server] IBS master keys saved" << std::endl;

    // Generate IBS user key and save to file
    std::cout << "[Server] Generating IBS user key for: " << user_id << std::endl;
    if (!ibs_pkg.generate_user_private_key(user_id, "sm9_ibs_user.key")) {
        std::cerr << "[Server] Failed to generate IBS user key" << std::endl;
        return 1;
    }
    std::cout << "[Server] IBS user key saved to sm9_ibs_user.key" << std::endl;

    std::cout << "\n[Server] PKG initialization complete." << std::endl;
    std::cout << "[Server] In production, private keys would be stored securely." << std::endl;

    return 0;
}
