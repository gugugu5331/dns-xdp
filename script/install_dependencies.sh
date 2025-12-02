#!/bin/bash
# install_dependencies.sh

set -e

echo "=== 安装基础依赖 ==="
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libelf-dev \
    clang \
    llvm \
    libbpf-dev

echo "=== 安装 C++ 开发依赖 ==="
sudo apt-get install -y \
    g++ \
    libgtest-dev \
    libbenchmark-dev

echo "=== 安装 Go ==="
GO_VERSION="1.21.5"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

echo "=== 验证安装 ==="
go version
g++ --version
cmake --version
clang --version

echo "=== 安装完成 ==="
