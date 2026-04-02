# 基础镜像
FROM ubuntu:24.04

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV MY_INSTALL_DIR=/root/.local
ENV PATH="$MY_INSTALL_DIR/bin:$PATH"

# 替换 APT 源为中科大源 (USTC)
RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak && \
    echo 'Types: deb\n\
URIs: http://mirrors.ustc.edu.cn/ubuntu\n\
Suites: noble noble-updates noble-backports\n\
Components: main restricted universe multiverse\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
\n\
Types: deb\n\
URIs: http://mirrors.ustc.edu.cn/ubuntu\n\
Suites: noble-security\n\
Components: main restricted universe multiverse\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' > /etc/apt/sources.list.d/ubuntu.sources

# 安装基础工具、依赖库
RUN apt-get update && apt-get install -y \
    cmake \
    vim \
    wget \
    net-tools \
    npm \
    ca-certificates \
    gnupg \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    libssl-dev \
    git \
    lsb-release \
    libargon2-dev \
    libgmp-dev \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# 安装 PBC 库 (Pairing-Based Cryptography)
# 依赖 GMP(已通过apt安装), flex, bison
# 注意：PBC 源码通常安装到 /usr/local/lib，需要刷新 ldconfig
WORKDIR /tmp
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make -j $(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# 编译并安装 gRPC v1.67.0
RUN mkdir -p $MY_INSTALL_DIR
WORKDIR /tmp
RUN git clone --recurse-submodules -b v1.67.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc && \
    cd grpc && \
    mkdir -p cmake/build && \
    cd cmake/build && \
    cmake -DgRPC_INSTALL=ON \
    -DgRPC_BUILD_TESTS=OFF \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
    -DgRPC_SSL_PROVIDER=package \
    ../.. && \
    make -j $(nproc) && \
    make install && \
    cd /tmp && rm -rf grpc



# 环境变量配置
RUN echo 'if [ -d "$HOME/.local/bin" ] ; then PATH="$HOME/.local/bin:$PATH" ; fi' >> /root/.bashrc

# 设置工作目录
WORKDIR /root

# 验证安装
RUN cmake --version && \
    protoc --version && \
    gmssl version || echo "GmSSL check requires args"