#!/bin/bash
# 安装运行依赖

echo "=========================================="
echo "安装 Python 依赖"
echo "=========================================="

echo "安装 numpy..."
sudo apt-get update
sudo apt-get install -y python3-numpy

echo ""
echo "验证安装:"
python3 -c "import numpy; print('✓ numpy 版本:', numpy.__version__)"

echo ""
echo "=========================================="
echo "依赖安装完成"
echo "=========================================="

