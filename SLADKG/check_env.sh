#!/bin/bash
# 检查运行环境

echo "=========================================="
echo "环境检查"
echo "=========================================="

echo "1. Python 版本:"
python3 --version

echo ""
echo "2. 检查依赖包:"
python3 << EOF
import sys
missing = []
try:
    import numpy
    print("  ✓ numpy")
except ImportError:
    missing.append("numpy")
    print("  ✗ numpy (缺失)")

try:
    import json
    print("  ✓ json (内置)")
except ImportError:
    missing.append("json")
    print("  ✗ json (缺失)")

try:
    import sys
    sys.path.insert(0, ".")
    from tongsuo import LIBCRYPTO_PATH
    print(f"  ✓ Tongsuo 库可用: {LIBCRYPTO_PATH}")
except Exception as e:
    missing.append("tongsuo")
    print(f"  ✗ Tongsuo 库: {e}")

if missing:
    print(f"\n缺失的依赖: {', '.join(missing)}")
    sys.exit(1)
else:
    print("\n✓ 所有依赖检查通过")
    sys.exit(0)
EOF

