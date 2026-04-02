// ABE gRPC Demo - Server
// This demo shows how to use ABE via gRPC
// The server runs as a remote PKG service

#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <grpcpp/grpcpp.h>
#include "abe/authority.h"
#include "serverInteraction.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using serverInteraction::AttributeAuthorityService;
using serverInteraction::GetABEPublicKeyRequest;
using serverInteraction::GetABEPublicKeyResponse;
using serverInteraction::GetABEPrivateKeyRequest;
using serverInteraction::GetABEPrivateKeyResponse;
using serverInteraction::ConvertPolicyRequest;
using serverInteraction::ConvertPolicyResponse;

namespace abe {

class GrpcAAServiceImpl final : public AttributeAuthorityService::Service {
public:
    GrpcAAServiceImpl() {
        authority_ = std::make_unique<AttributeAuthority>();
    }

    AttributeAuthority* get_authority() { return authority_.get(); }

    Status GetABEPublicKey(ServerContext* context,
                           const GetABEPublicKeyRequest* request,
                           GetABEPublicKeyResponse* response) override {
        int key_id = request->key_id();
        std::cout << "[gRPC Server] GetABEPublicKey, key_id = " << key_id << std::endl;
        std::string pk_json = authority_->get_public_key_json(key_id);
        response->set_abe_public_key(pk_json);
        return Status::OK;
    }

    Status GetABEPrivateKey(ServerContext* context,
                           const GetABEPrivateKeyRequest* request,
                           GetABEPrivateKeyResponse* response) override {
        int layer = request->layer();
        std::vector<std::string> attrs(request->attrs().begin(), request->attrs().end());
        std::cout << "[gRPC Server] GetABEPrivateKey, layer = " << layer
                  << ", attrs = " << attrs.size() << std::endl;
        std::string sk_json = authority_->generate_private_key_json(layer, attrs);
        response->set_abe_secret_key(sk_json);
        return Status::OK;
    }

    Status ConvertPolicy(ServerContext* context,
                        const ConvertPolicyRequest* request,
                        ConvertPolicyResponse* response) override {
        int layer = request->layer();
        std::string policy = request->policy();
        std::cout << "[gRPC Server] ConvertPolicy, layer = " << layer
                  << ", policy = " << policy << std::endl;
        std::string converted = authority_->convert_policy(layer, policy);
        response->set_converted_policy(converted);
        return Status::OK;
    }

private:
    std::unique_ptr<AttributeAuthority> authority_;
};

}  // namespace abe

int main(int argc, char** argv) {
    std::string server_address = "0.0.0.0:50057";
    std::string param_file = "a.param";
    int max_attrs = 10;

    std::cout << "=== ABE gRPC Demo - Server ===" << std::endl;
    std::cout << "[Server] Starting on " << server_address << std::endl;

    abe::GrpcAAServiceImpl service;

    // Initialize authority
    if (!service.get_authority()->initialize(param_file, max_attrs)) {
        std::cerr << "[Server] Failed to initialize authority" << std::endl;
        return 1;
    }

    // Custom attribute mapping (optional)
    std::unordered_map<std::string, int> attr_map = {
        {"role:admin", 1}, {"clearance:high", 2}, {"dept:finance", 3},
        {"role:user", 4}, {"clearance:low", 5}, {"dept:hr", 6},
        {"team:alpha", 7}, {"team:beta", 8}, {"project:X", 9}, {"project:Y", 10}
    };
    service.get_authority()->set_attribute_map(1, attr_map);
    service.get_authority()->set_attribute_map(2, attr_map);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "[Server] ABE Authority Server started" << std::endl;
    server->Wait();

    return 0;
}
