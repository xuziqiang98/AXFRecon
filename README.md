# AXFRecon - DNS域传送漏洞检测工具

一个简单而高效的DNS域传送漏洞检测工具，可以自动收集子域名并检测DNS服务器是否存在域传送漏洞。

## 功能特点

- 自动获取目标域名的NS记录
- 检测DNS服务器是否存在域传送漏洞
- 自动收集子域名信息
- 实时显示检测进度
- 将检测结果保存到文件

## 安装

1. 克隆仓库：
```bash
git clone https://github.com/yourusername/AXFRecon.git
cd AXFRecon
```

2. 安装依赖：

首先安装uv包管理器（如果尚未安装）：
```bash
pip install -U uv
```

创建并激活虚拟环境：
```bash
uv venv venv
source venv/bin/activate  # Linux/macOS
# 或者在Windows上使用：
# venv\Scripts\activate
```

然后使用uv安装项目依赖：
```bash
uv pip install -r requirements.txt
```

3. 添加执行权限：
```bash
chmod +x axfrecon.py
```

## 使用方法

基本使用：
```bash
./axfrecon.py example.com
```

指定输出文件：
```bash
./axfrecon.py example.com -o custom_output.txt
```

关闭子域名扫描：
```bash
./axfrecon.py example.com -s false
```

从文件读取域名列表：
```bash
./axfrecon.py -f domains.txt
```

## 参数说明

- `domain`: 要检测的域名（使用-f参数时可选）
- `-f, --file`: 从文本文件读取域名列表（每行一个域名）
- `-s, --scan-subdomains`: 是否开启子域名扫描（默认开启，使用-f参数时默认关闭）
- `-o, --output`: 指定输出文件路径（默认为results.txt）

## 输出示例

```
[*] 开始检测域名: example.com

[*] 正在获取NS记录...
[+] 发现 2 个DNS服务器

检测进度: 100%|██████████| 2/2 [00:02<00:00,  1.00it/s]

[*] 检测完成

[!] 发现存在漏洞的DNS服务器:
    - ns1.example.com

[+] 发现 15 个子域名

[+] 结果已保存到: example.com.txt
```

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。