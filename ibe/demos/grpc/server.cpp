// IBE gRPC Demo - Server
// This demo shows how to use IBE via gRPC
// The server runs as a remote PKG service

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <grpcpp/grpcpp.h>
#include "ibe/pkg_service.h"
#include "ibe.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using ibe::IbeService;
using ibe::MasterPub;
using ibe::UserId;
using ibe::UserPriv;
using google::protobuf::Empty;

namespace ibe {

class GrpcIbeServiceImpl final : public IbeService::Service {
public:
    GrpcIbeServiceImpl() {
        pkg_service_ = std::make_unique<PkgService>();
    }

    bool initialize(const std::string& master_key_file,
                   const std::string& master_pub_file) {
        return pkg_service_->initialize(master_key_file, master_pub_file);
    }

    Status GetIBEMasterPublic(ServerContext* ctx, const Empty* /*req*/, MasterPub* resp) override {
        std::vector<uint8_t> der = pkg_service_->get_master_public_der();
        if (der.empty()) {
            return Status(grpc::NOT_FOUND, "IBE master public key not found");
        }
        resp->set_der(std::string((char*)der.data(), der.size()));
        return Status::OK;
    }

    Status GetIBEUserPrivateKey(ServerContext* ctx, const UserId* req, UserPriv* resp) override {
        std::vector<uint8_t> der = pkg_service_->generate_user_private_key_der(req->id());
        if (der.empty()) {
            return Status(grpc::INTERNAL, "Failed to export user private key");
        }
        resp->set_der(std::string((char*)der.data(), der.size()));
        return Status::OK;
    }

    Status GetIBSMasterPublic(ServerContext* ctx, const Empty* /*req*/, MasterPub* resp) override {
        return Status(grpc::UNIMPLEMENTED, "IBS not yet implemented");
    }

    Status GetIBSUserPrivateKey(ServerContext* ctx, const UserId* req, UserPriv* resp) override {
        return Status(grpc::UNIMPLEMENTED, "IBS not yet implemented");
    }

private:
    std::unique_ptr<PkgService> pkg_service_;
};

}  // namespace ibe

int main(int argc, char** argv) {
    std::string server_address = "0.0.0.0:50051";
    std::string master_key_file = "sm9_ibe_master.key";
    std::string master_pub_file = "sm9_ibe_master.pub";

    std::cout << "=== IBE gRPC Demo - Server ===" << std::endl;
    std::cout << "[Server] Starting on " << server_address << std::endl;

    ibe::GrpcIbeServiceImpl service;

    if (!service.initialize(master_key_file, master_pub_file)) {
        std::cerr << "[Server] Failed to initialize PKG service" << std::endl;
        return 1;
    }

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "[Server] IBE PKG Server started" << std::endl;
    server->Wait();

    return 0;
}
