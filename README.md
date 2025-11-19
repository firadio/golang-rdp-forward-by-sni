# RDP Forward by SNI

一个基于SNI（Server Name Indication）的TCP转发工具，主要用于RDP协议的智能转发和访问控制。

## 功能特性

- ✅ **SNI白名单过滤**：根据TLS握手中的SNI信息进行访问控制
- ✅ **RDP协议支持**：完整支持RDP协议的连接协商和TLS升级流程
- ✅ **透明转发**：对应用层透明的TCP流量转发
- ✅ **详细日志**：支持DEBUG模式，提供详细的连接和数据包信息
- ✅ **连接追踪**：每个连接带有唯一ID和客户端IP地址标识
- ✅ **优雅的错误处理**：智能的连接生命周期管理，避免误导性错误日志

## 快速开始

### 编译

```bash
go build -o rdp-forward main.go
```

或在Windows上:

```bash
go build -o rdp-forward.exe
```

### 基本使用（控制台模式）

```bash
# 监听3389端口，转发到本地28820端口
./rdp-forward -target 127.0.0.1:28820

# 指定监听端口
./rdp-forward -listen :3390 -target 192.168.1.100:3389

# 启用SNI白名单（域名）
./rdp-forward -target 127.0.0.1:3389 -sni "rdp.example.com,rdp2.example.com"

# 启用SNI白名单（IP地址）
./rdp-forward -target 127.0.0.1:3389 -sni "192.168.1.100,10.0.0.50"

# 启用SNI白名单（域名和IP混合）
./rdp-forward -target 127.0.0.1:3389 -sni "rdp.example.com,192.168.1.100"

# 启用DEBUG模式查看详细日志
./rdp-forward -target 127.0.0.1:3389 -sni "rdp.example.com" -debug
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `:3389` | 监听地址和端口 |
| `-target` | **必填** | 目标服务器地址（格式：`IP:端口`） |
| `-sni` | 空（允许所有） | SNI白名单，多个域名用逗号分隔 |
| `-debug` | `false` | 启用DEBUG模式，显示详细的数据包信息 |
| `-service` | 空 | Windows服务命令：install, uninstall, start, stop |

## Windows服务模式

程序支持作为Windows服务运行，实现开机自启和后台运行。

### 安装服务

```powershell
# 以管理员身份运行
.\rdp-forward.exe -service install -listen :3389 -target 127.0.0.1:28820 -sni "rdp.example.com"
```

### 启动服务

```powershell
.\rdp-forward.exe -service start
# 或使用Windows服务管理
sc start RDPForwardBySNI
```

### 停止服务

```powershell
.\rdp-forward.exe -service stop
# 或使用Windows服务管理
sc stop RDPForwardBySNI
```

### 卸载服务

```powershell
.\rdp-forward.exe -service uninstall
```

### 查看服务状态

```powershell
sc query RDPForwardBySNI
```

### 查看服务日志

服务运行时会在程序所在目录生成日志文件：

```powershell
# 查看日志文件（假设程序在C:\Program Files\RDPForward目录）
type "C:\Program Files\RDPForward\rdp-forward.log"

# 或使用记事本打开
notepad "C:\Program Files\RDPForward\rdp-forward.log"

# 实时监控日志（使用PowerShell）
Get-Content "C:\Program Files\RDPForward\rdp-forward.log" -Wait -Tail 50
```

日志文件位置：`程序所在目录\rdp-forward.log`

**注意**：
- 安装/卸载/启动/停止服务需要管理员权限
- 服务名称：`RDPForwardBySNI`
- 服务显示名称：`RDP Forward by SNI`
- 服务会自动设置为开机自启动
- 服务日志会写入到与可执行文件相同目录的`rdp-forward.log`文件中

## 工作原理

### RDP连接流程

```
客户端 → 监听端口 → RDP协议协商 → TLS升级 → SNI提取 → 白名单检查 → 透明转发
```

1. **客户端连接** → 程序监听端口
2. **RDP协议协商** → 客户端发送协议协商包（0x03）
3. **TLS升级** → 协商完成后升级到TLS连接
4. **SNI提取** → 从TLS ClientHello中提取SNI
5. **白名单检查** → 如果配置了白名单，验证SNI是否在列表中
6. **透明转发** → 双向转发所有数据包

### SNI白名单机制

当配置了`-sni`参数后：
- ✅ SNI在白名单中 → 允许连接并转发
- ❌ SNI不在白名单中 → **断开连接**
- ❌ RDP协商后未升级到TLS → **断开连接**（防止绕过SNI检查，超过3个包未检测到TLS）

当未配置`-sni`参数时：
- ✅ 允许所有连接（不进行SNI检查、允许非TLS的RDP连接）

**安全机制**：
- RDP连接流程：协商（0x03包）→ TLS升级（0x16包）→ SNI提取与检查
- 配置白名单后，必须在前3个包内完成TLS升级，否则视为绕过攻击
- 白名单可以包含域名、IP地址或两者混合，只有匹配的SNI才能通过

## 日志说明

### 正常模式

```
[2025-11-20 12:34:56] [INFO] 监听端口: :3389
[2025-11-20 12:34:56] [INFO] 转发目标: 127.0.0.1:28820
[2025-11-20 12:34:56] [INFO] SNI白名单: rdp.example.com
[2025-11-20 12:34:56] [INFO] 等待连接...
[2025-11-20 12:35:10] [INFO] [连接#1,192.168.1.100:54321] [SNI] rdp.example.com
```

### DEBUG模式

```
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] 新连接
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] 已连接到目标 127.0.0.1:28820
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] [包#1] 客户端->服务器: 512 字节
  前32字节: 030000...
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] → RDP协议协商包 (等待TLS升级)
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] ✓ 检测到TLS握手包
[2025-11-20 12:35:10] [INFO] [连接#1,192.168.1.100:54321] [SNI] rdp.example.com
[2025-11-20 12:35:10] [DEBUG] [连接#1,192.168.1.100:54321] ✓ SNI在白名单中
```

### 日志级别

- **INFO**：关键信息（启动配置、SNI检测）
- **WARN**：警告信息（SNI不在白名单）
- **ERROR**：错误信息（连接失败、网络错误）
- **DEBUG**：调试信息（需要`-debug`参数，包含详细的数据包信息）

## 使用场景

### 1. 多租户RDP服务

通过SNI区分不同的客户端，转发到不同的RDP服务器：

```bash
# 只允许指定域名的客户端访问
./rdp-forward -target 10.0.0.100:3389 -sni "tenant1.rdp.company.com,tenant2.rdp.company.com"
```

### 2. RDP访问控制

限制只有特定SNI的客户端才能连接（可以是域名或IP地址）：

```bash
# 只允许特定域名
./rdp-forward -target localhost:3389 -sni "secure.rdp.internal"

# 只允许特定IP地址的客户端
./rdp-forward -target localhost:3389 -sni "192.168.1.100,192.168.1.101"
```

### 3. RDP流量监控

在DEBUG模式下监控RDP连接的详细信息：

```bash
./rdp-forward -target 192.168.1.50:3389 -debug
```

## 技术细节

### TLS ClientHello解析

程序实现了完整的TLS ClientHello解析逻辑：
- 支持解析TLS 1.0 - 1.3的ClientHello
- 正确处理Session ID、Cipher Suites、Compression Methods
- 从Extensions中提取SNI（扩展类型0x0000）

### RDP协议兼容性

- 支持RDP 5.0+的协议协商
- 兼容CredSSP (Network Level Authentication)
- 支持TLS升级流程

### 连接管理

- 使用goroutine实现高并发连接处理
- 智能的连接生命周期管理，避免资源泄漏
- 优雅的错误处理，第一个方向断开时立即关闭另一个方向

## 性能特点

- **低延迟**：直接的TCP转发，无额外处理开销
- **高并发**：每个连接独立的goroutine处理
- **内存高效**：固定大小的缓冲区（4KB）
- **连接数无限制**：受限于操作系统而非程序本身

## 安全建议

1. **使用防火墙**：限制可以连接到监听端口的IP地址
2. **配置SNI白名单**：避免未授权访问
3. **监控日志**：定期检查访问日志，发现异常连接
4. **定期更新**：保持程序在最新版本

## 故障排查

### 连接被拒绝

```
[WARN] [连接#1,192.168.1.100:54321] ❌ SNI不在白名单中，断开连接
```
**解决方法**：检查客户端证书的SNI是否在白名单中，或移除`-sni`参数允许所有连接。

### RDP协商后未检测到TLS升级

```
[WARN] [连接#1,192.168.1.100:54321] ❌ RDP协商后未检测到TLS升级，可能是绕过SNI检查，断开连接
```
**原因**：
- 客户端在RDP协商后没有升级到TLS连接
- 可能是攻击者尝试绕过SNI白名单检查
- 客户端配置错误，未启用TLS

**解决方法**：
- **推荐做法**：保持配置白名单，确保RDP客户端正确配置并启用TLS/SSL
- 检查RDP客户端的安全设置，确保"要求使用网络级别身份验证"已启用
- 如果需要允许非TLS的RDP连接：移除`-sni`参数（极不推荐，严重降低安全性）

### 连接目标失败

```
[ERROR] [连接#1,192.168.1.100:54321] 连接目标失败: dial tcp 127.0.0.1:28820: connect: connection refused
```
**解决方法**：检查目标服务器是否正在运行并监听指定端口。

## 开发

### 项目结构

```
.
├── main.go           # 主程序文件
├── README.md         # 项目文档
└── rdp-forward       # 编译后的可执行文件
```

### 代码架构

- **面向对象设计**：使用`Connection`对象封装连接上下文
- **统一日志接口**：`logInfo()`, `logWarn()`, `logError()`, `logDebug()`
- **goroutine并发**：客户端→服务器、服务器→客户端双向独立转发
- **Channel通信**：使用error channel协调goroutine生命周期

### 贡献指南

欢迎提交Issue和Pull Request！

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交改动 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 许可证

MIT License

## 作者

[firadio](https://github.com/firadio)

## 致谢

本项目使用Go语言开发，感谢Go语言团队提供的优秀工具链。
