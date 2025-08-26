# MCP Kali Server

**Kali MCP 服务器** 是一个轻量级的 API 桥接器，它将 MCP 客户端（例如：Claude Desktop、[5ire](https://github.com/nanbingxyz/5ire)）连接到 API 服务器，从而允许在 Linux 终端上执行命令。

这使得 MCP 能够运行 `nmap`、`nxc` 或任何其他工具等终端命令，并使用 `curl`、`wget`、`gobuster` 等工具与 Web 应用程序交互。
此外，它还能执行**AI 辅助渗透测试**，实时解决**CTF Web 挑战**，帮助**解决 HTB 或 THM 中的机器问题**。

**V1.0版本**是https://github.com/Wh0am123/MCP-Kali-Server.git 的**原版**，不做多介绍

此版本为**V2.0版本**是根据https://github.com/Wh0am123/MCP-Kali-Server.git **为基础，进行了更改，完善了数据传输方面的安全风险。**

## 我关于此工具的 文章

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**MCP 如何革新进攻性安全**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## 🔍 用例

目标是通过以下方式实现 AI 驱动的攻击性安全测试：

- 让 MCP 与 OpenAI、Claude、DeepSeek 或任何其他模型等 AI 端点交互。
- 公开 API 以在 Kali 机器上执行命令。
- 使用 AI 建议并运行终端命令来解决 CTF 挑战或自动执行侦察/漏洞利用任务。
- 允许 MCP 应用发送自定义请求（例如 `curl`、`nmap`、`ffuf` 等）并接收结构化输出。

以下是我的一些测试示例（我使用了谷歌的 AI `gemini 2.0 flash`）。

### Example solving my web CTF challenge in RamadanCTF
https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB
https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27


---

## 🚀 功能

- 🧠 **AI 终端集成**：将您的 Kali 连接到您喜欢的任何 MCP，例如 Claude Desktop 或 5ier。
- 🖥️ **命令执行 API**：公开受控 API，用于在您的 Kali Linux 计算机上执行终端命令。
- 🕸️ **Web 挑战赛支持**：AI 可以与网站和 API 交互，通过 `curl` 以及任何其他 AI 需要的工具捕获 flag。
- 🔐 **专为进攻型安全专业人士设计**：非常适合红队成员、漏洞赏金猎人或 CTF 玩家自动执行常见任务。

---

## 🛠️ 安装

### 在您的 Linux 机器上（将充当 MCP 服务器）

```bash
git clone https://github.com/AeolusTF/MCP-Kali-Server-security.git
cd MCP-Kali-Server
python3 kali_server.py
```

### 在您的 MCP 客户端上（您可以在 Windows 或 Linux 上运行）

- 您需要运行 `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000`

#### Claude 桌面配置：

edit (C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json)

```json
{
    "mcpServers": {
        "kali_mcp": {
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "http://LINUX_IP:5000/"
            ]
        }
    }
}
```

#### [5ire](https://github.com/nanbingxyz/5ire) 桌面应用程序的配置：

- 只需使用命令 `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000` 添加 MCP，它就会自动生成所需的配置文件。

## 🔮 其他可能性

由于 AI 模型现在可以在终端上执行命令，因此可能性远不止于此。以下是一些示例：

- 使用 Volatility 进行内存取证
- 自动执行内存分析任务，例如进程枚举、DLL 注入检查以及从内存转储中提取注册表。

- 使用 SleuthKit 进行磁盘取证
- 自动执行磁盘映像分析、时间线生成、文件雕刻和哈希值比较。

## ⚠️ 免责声明：

本项目仅用于教育和道德测试目的。严禁任何滥用本站信息或工具的行为，包括未经授权的访问、漏洞利用或恶意活动。
作者对任何滥用行为概不负责。
