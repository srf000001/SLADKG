# 快速开始指南

## 在 WSL 中运行 DKG 程序

### 步骤 1: 打开 WSL 终端

在 Windows PowerShell 中运行：
```powershell
wsl
```

或者在 Windows 开始菜单搜索 "Ubuntu" 或 "WSL"

### 步骤 2: 进入项目目录

```bash
cd /mnt/g/2026/0127DSN-USENIX/Paper/仓库/SLADKG
```

### 步骤 3: 安装依赖（首次运行需要）

```bash
sudo apt-get update
sudo apt-get install -y python3-numpy
```

**注意**: 这会要求输入 sudo 密码

### 步骤 4: 验证环境

```bash
bash check_env.sh
```

应该看到所有依赖都检查通过。

### 步骤 5: 运行程序

**方法 1: 使用运行脚本（推荐）**
```bash
bash run_dkg.sh
```

**方法 2: 直接运行**
```bash
python3 SLACSS.py
```

## 完整命令序列

```bash
# 1. 进入 WSL
wsl

# 2. 进入项目目录
cd /mnt/g/2026/0127DSN-USENIX/Paper/仓库/SLADKG

# 3. 安装依赖（只需一次）
sudo apt-get update
sudo apt-get install -y python3-numpy

# 4. 运行程序
python3 SLACSS.py
```

## 预期输出

程序运行时会显示：
- DKG 协议执行过程
- 参与者状态
- 性能统计信息
- 日志文件保存在 `log/` 目录

## 如果遇到问题

1. **找不到 numpy**: 运行 `sudo apt-get install python3-numpy`
2. **找不到 Tongsuo 库**: 运行 `python3 Tongsuo/verify_build.py` 验证
3. **权限错误**: 运行 `chmod +x *.sh`

## 更多信息

详细说明请查看 `RUN_INSTRUCTIONS.md`

