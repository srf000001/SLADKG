#!/bin/bash
# 运行 DKG 程序

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "运行 Lattice-Based DKG 程序"
echo "=========================================="
echo "工作目录: $SCRIPT_DIR"
echo ""

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到 python3"
    exit 1
fi

echo "Python 版本:"
python3 --version
echo ""

# 检查依赖
echo "检查依赖..."
python3 << 'PYTHON_CHECK'
import sys
missing = []

try:
    import numpy
    print("  ✓ numpy")
except ImportError:
    missing.append("numpy")
    print("  ✗ numpy (缺失)")

try:
    import sys
    sys.path.insert(0, ".")
    from tongsuo import LIBCRYPTO_PATH
    print(f"  ✓ Tongsuo 库: {LIBCRYPTO_PATH}")
except Exception as e:
    missing.append("tongsuo")
    print(f"  ✗ Tongsuo 库: {e}")

if missing:
    print(f"\n错误: 缺失依赖: {', '.join(missing)}")
    print("请先运行: bash install_dependencies.sh")
    sys.exit(1)
PYTHON_CHECK

if [ $? -ne 0 ]; then
    exit 1
fi

echo ""
echo "=========================================="
echo "启动 DKG 程序..."
echo "=========================================="
echo ""

# 运行主程序
python3 SLACSS.py

