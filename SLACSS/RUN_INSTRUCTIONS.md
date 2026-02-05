# 在 WSL 中运行 DKG 程序

## 快速开始

### 1. 安装依赖（首次运行需要）

在 WSL 终端中执行：

```bash
cd /mnt/g/2026/0127DSN-USENIX/Paper/仓库/SLACSS
bash install_dependencies.sh
```

这会安装所需的 Python 包（主要是 numpy）。

### 2. 运行程序

```bash
bash run_dkg.sh
```

或者直接运行：

```bash
python3 V3S_DKG.py
```

## 手动安装依赖

如果脚本无法运行，可以手动安装：

```bash
# 更新包列表
sudo apt-get update

# 安装 numpy
sudo apt-get install -y python3-numpy

# 验证安装
python3 -c "import numpy; print('numpy 版本:', numpy.__version__)"
```

## 环境要求

- Python 3.10.12 或更高版本（当前: Python 3.12.3）
- numpy
- Tongsuo 库（已编译，位于 `Tongsuo/libcrypto.so`）

## 验证环境

运行环境检查脚本：

```bash
bash check_env.sh
```

## 程序输出

程序运行时会：
1. 创建日志目录 `log/`
2. 输出详细的协议执行过程
3. 显示性能统计信息

日志文件会保存在 `log/` 目录中，文件名格式：`YYYYMMDD-NNN.log`

## 故障排除

### 问题：找不到 numpy

**解决方案**：
```bash
sudo apt-get install python3-numpy
```

### 问题：找不到 Tongsuo 库

**解决方案**：
- 确保 `Tongsuo/libcrypto.so` 文件存在
- 运行验证脚本：`python3 Tongsuo/verify_build.py`

### 问题：权限错误

**解决方案**：
```bash
chmod +x *.sh
```

## 注意事项

- 程序需要在 WSL 环境中运行（因为使用的是 Linux 版本的 Tongsuo 库）
- 首次运行可能需要几分钟来执行完整的 DKG 协议
- 确保有足够的磁盘空间用于日志文件

