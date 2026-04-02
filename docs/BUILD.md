# ABE/IBE 模块化编译文档

## 环境要求

- CMake >= 3.14
- C++ 编译器 (支持 C++14)
- Protocol Buffers >= 3.15
- gRPC >= 1.40
- PBC (Pairing-Based Cryptography) 库
- GMP (GNU Multiple Precision Arithmetic) 库
- GmSSL 库 (仅 IBE 模块需要)

## 目录结构

```
/SAwork/
├── abe/                           # ABE 模块
│   ├── CMakeLists.txt             # 顶层聚合
│   ├── a.param                    # PBC 配对参数文件
│   ├── serverInteraction.proto    # ABE gRPC 协议定义
│   ├── lib/abe_core/             # ABE 核心静态库
│   │   ├── CMakeLists.txt
│   │   ├── include/              # 头文件
│   │   └── *.cpp                 # 源文件
│   └── demos/
│       ├── direct/               # 直接接口调用示例
│       │   ├── CMakeLists.txt
│       │   ├── server.cpp        # 生成密钥到文件
│       │   └── client.cpp        # 从文件加载密钥加解密
│       └── grpc/                 # gRPC 远程调用示例
│           ├── CMakeLists.txt
│           ├── server.cpp        # gRPC 服务器
│           └── client.cpp        # gRPC 客户端
│
└── ibe/                           # IBE 模块
    ├── CMakeLists.txt             # 顶层聚合
    ├── ibe.proto                  # IBE gRPC 协议定义
    ├── lib/ibe_core/             # IBE 核心静态库
    │   ├── CMakeLists.txt
    │   ├── sm9_ibe.h/cpp         # SM9 IBE 实现
    │   ├── sm9_ibs.h/cpp         # SM9 IBS 实现
    │   ├── io.h                  # 文件读写工具
    │   ├── pkg_service.cpp       # PKG 服务实现
    │   └── include/
    │       └── ibe/pkg_service.h  # PKG 服务接口
    └── demos/
        ├── direct/               # 直接接口调用示例
        │   ├── CMakeLists.txt
        │   ├── server.cpp        # 生成密钥
        │   └── client.cpp        # 加解密、签名验签
        └── grpc/                 # gRPC 远程调用示例
            ├── CMakeLists.txt
            ├── server.cpp
            └── client.cpp
```

---

## 1. 依赖安装

### Ubuntu/Debian

```bash
# 安装基础依赖
sudo apt-get update
sudo apt-get install -y build-essential cmake git

# 安装 GMP,flex,bison
sudo apt-get install -y libgmp-dev flex bison

# 安装 PBC (需要从源码编译)
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
tar xvf pbc-0.5.14.tar.gz && \
cd pbc-0.5.14 && \
./configure && \
make -j $(nproc) && \
sudo make install && \
sudo ldconfig && \
cd /tmp && rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# 安装 Protobuf 和 gRPC
git clone --recurse-submodules -b v1.67.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc && \
cd grpc && \
mkdir -p cmake/build && \
cd cmake/build && \
cmake -DgRPC_INSTALL=ON \
-DgRPC_BUILD_TESTS=OFF \
-DCMAKE_CXX_STANDARD=17 \
-DgRPC_SSL_PROVIDER=package \
-Dprotobuf_INSTALL=/root/.local \
../.. && \
make -j $(nproc) && \
sudo make install && \
cd /tmp && rm -rf grpc

# 安装 GmSSL (仅 IBE 需要)
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
./configure
make
sudo make install
sudo ldconfig
```

---

## 2. CMake 构建选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `CMAKE_BUILD_TYPE` | 构建类型 (Debug/Release) | Release |
| `GMSSL_ROOT` | GmSSL 安装路径 | /usr/local |
| `CMAKE_PREFIX_PATH` | gRPC/Protobuf 安装路径 | /root/.local |

---

## 3. 编译步骤

### 3.1 编译 ABE 模块

```bash
cd ./SAwork/abe
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

**输出：**
- `libabe_core.a` - ABE 核心静态库
- `abe_server` (direct) - 直接接口服务端可执行文件
- `abe_client` (direct) - 直接接口客户端可执行文件
- `abe_grpc_server` (grpc) - gRPC 服务器可执行文件
- `abe_grpc_client` (grpc) - gRPC 客户端可执行文件

### 3.2 编译 IBE 模块

```bash
cd ./SAwork/ibe
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

**输出：**
- `libibe_core.a` - IBE 核心静态库
- `ibe_server` (direct) - 直接接口服务端可执行文件
- `ibe_client` (direct) - 直接接口客户端可执行文件
- `ibe_grpc_server` (grpc) - gRPC 服务器可执行文件
- `ibe_grpc_client` (grpc) - gRPC 客户端可执行文件

---

## 4. 运行测试

### 4.1 ABE 直接接口测试

```bash
# 终端 1: 启动服务端（生成密钥）
cd ./SAwork/abe/build/demos/direct
./abe_server

# 终端 2: 运行客户端（加解密）
cd ./SAwork/abe/build/demos/direct
./abe_client
```

### 4.2 ABE gRPC 测试

```bash
# 终端 1: 启动 gRPC 服务器
cd ./SAwork/abe/build/demos/grpc
./abe_grpc_server &

# 终端 2: 运行 gRPC 客户端
cd ./SAwork/abe/build/demos/grpc
./abe_grpc_client
```

### 4.3 IBE 直接接口测试

```bash
# 终端 1: 启动服务端（生成密钥）
cd ./SAwork/ibe/build/demos/direct
./ibe_server

# 终端 2: 运行客户端（加解密、签名验签）
cd ./SAwork/ibe/build/demos/direct
./ibe_client
```

### 4.4 IBE gRPC 测试

```bash
# 终端 1: 启动 gRPC 服务器
cd ./SAwork/ibe/build/demos/grpc
./ibe_grpc_server &

# 终端 2: 运行 gRPC 客户端
cd ./SAwork/ibe/build/demos/grpc
./ibe_grpc_client
```

---

## 5. 完整构建脚本

```bash
#!/bin/bash
set -e

echo "=== Building ABE Module ==="
cd ./SAwork/abe
rm -rf build
mkdir build && cd build
cmake ..
make -j$(nproc)

echo "=== Building IBE Module ==="
cd ./SAwork/ibe
rm -rf build
mkdir build && cd build
cmake ..
make -j$(nproc)

echo "=== Build Complete ==="
```

---

## 6. 常见问题

### 6.1 PBC 库找不到

```bash
# 设置 PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
sudo ldconfig
```

### 6.2 gRPC 插件找不到

```bash
# 确保使用 cmake Build 配置
cd ./SAwork/abe
mkdir -p build && cd build
cmake .. -DCMAKE_PREFIX_PATH=/root/.local
```

### 6.3 GmSSL 库找不到

```bash
# 手动指定路径
cmake .. \
    -DGMSSL_ROOT=/usr/local \
    -DGMSSL_LIBRARY=/usr/local/lib/libgmssl.so \
    -DGMSSL_INCLUDE_DIR=/usr/local/include
```

### 6.4 Protobuf 版本不兼容

```bash
# 检查版本
protoc --version
grpc_cpp_plugin --version
```

### 6.5 编译错误：undefined reference to `pbc_param_init`

```bash
# PBC 库需要手动链接
sudo ln -s /usr/local/lib/libpbc.so /usr/lib/libpbc.so
sudo ldconfig
```

---

## 7. 模块依赖关系

```
abe_core (静态库)
├── PBC
├── GMP
└── absl::check
    ↓
demos/direct (直接接口示例)
    ↓
demos/grpc (gRPC 示例)
├── abe_core
├── gRPC
└── Protobuf

ibe_core (静态库)
├── GmSSL
├── PBC
├── GMP
└── absl::check
    ↓
demos/direct (直接接口示例)
    ↓
demos/grpc (gRPC 示例)
├── ibe_core
├── gRPC
└── Protobuf
```

---

## 8. 验证编译成功

```bash
# ABE 直接接口示例
ls -la ./SAwork/abe/build/demos/direct/abe_server
ls -la ./SAwork/abe/build/demos/direct/abe_client

# ABE gRPC 示例
ls -la ./SAwork/abe/build/demos/grpc/abe_grpc_server
ls -la ./SAwork/abe/build/demos/grpc/abe_grpc_client

# IBE 直接接口示例
ls -la ./SAwork/ibe/build/demos/direct/ibe_server
ls -la ./SAwork/ibe/build/demos/direct/ibe_client

# IBE gRPC 示例
ls -la ./SAwork/ibe/build/demos/grpc/ibe_grpc_server
ls -la ./SAwork/ibe/build/demos/grpc/ibe_grpc_client
```
