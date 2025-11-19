package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenPort   string
	TargetAddr   string
	Whitelist    map[string]bool
	WhitelistStr string
	Debug        bool
}

// Connection 连接对象
type Connection struct {
	config     *Config
	connID     int
	clientAddr string
}

// NewConnection 创建新的连接对象
func NewConnection(config *Config, connID int, clientAddr string) *Connection {
	return &Connection{
		config:     config,
		connID:     connID,
		clientAddr: clientAddr,
	}
}

// 连接对象的日志方法
func (c *Connection) logInfo(format string, args ...interface{}) {
	logMsg(c.config, LogLevelINFO, c.connID, c.clientAddr, format, args...)
}

func (c *Connection) logWarn(format string, args ...interface{}) {
	logMsg(c.config, LogLevelWARN, c.connID, c.clientAddr, format, args...)
}

func (c *Connection) logError(format string, args ...interface{}) {
	logMsg(c.config, LogLevelERROR, c.connID, c.clientAddr, format, args...)
}

func (c *Connection) logDebug(format string, args ...interface{}) {
	logMsg(c.config, LogLevelDEBUG, c.connID, c.clientAddr, format, args...)
}

// 自定义错误类型
var ErrSNINotInWhitelist = errors.New("SNI not in whitelist")

// 日志级别
const (
	LogLevelINFO  = "INFO"
	LogLevelWARN  = "WARN"
	LogLevelERROR = "ERROR"
	LogLevelDEBUG = "DEBUG"
)

// 统一日志函数
func logMsg(config *Config, level string, connID int, clientAddr string, format string, args ...interface{}) {
	// 根据调试模式和日志级别决定是否打印
	// 非DEBUG模式下: 只打印INFO/WARN/ERROR
	// DEBUG模式下: 打印所有级别
	if !config.Debug && level == LogLevelDEBUG {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	if connID > 0 {
		if clientAddr != "" {
			fmt.Printf("[%s] [%s] [连接#%d,%s] %s\n", timestamp, level, connID, clientAddr, message)
		} else {
			fmt.Printf("[%s] [%s] [连接#%d] %s\n", timestamp, level, connID, message)
		}
	} else {
		fmt.Printf("[%s] [%s] %s\n", timestamp, level, message)
	}
}

// 从 TLS ClientHello 中提取 SNI
func extractSNI(data []byte) (string, error) {
	if len(data) < 43 {
		return "", fmt.Errorf("data too short")
	}

	// 检查是否是 TLS Handshake (0x16)
	if data[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake")
	}

	// 检查是否是 ClientHello (0x01)
	if data[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}

	// 跳过固定部分
	pos := 43 // TLS header (5) + Handshake header (4) + Version (2) + Random (32)

	// Session ID
	if pos >= len(data) {
		return "", nil
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher Suites
	if pos+2 > len(data) {
		return "", nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherSuitesLen

	// Compression Methods
	if pos >= len(data) {
		return "", nil
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// Extensions
	if pos+2 > len(data) {
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2

	extensionsEnd := pos + extensionsLen
	for pos+4 <= extensionsEnd && pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos:])
		extLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4

		if pos+extLen > len(data) {
			break
		}

		// SNI Extension (0x0000)
		if extType == 0x0000 {
			if extLen < 2 {
				break
			}
			// Server Name List Length
			pos += 2
			extLen -= 2

			if extLen < 3 {
				break
			}
			// Server Name Type (0x00 for hostname)
			if data[pos] == 0x00 {
				pos++
				nameLen := int(binary.BigEndian.Uint16(data[pos:]))
				pos += 2
				if pos+nameLen <= len(data) {
					return string(data[pos : pos+nameLen]), nil
				}
			}
		}
		pos += extLen
	}

	return "", nil
}

// runServer 运行转发服务器
func runServer(config *Config, stopCh <-chan struct{}) {
	// 监听端口
	listener, err := net.Listen("tcp", config.ListenPort)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	logMsg(config, LogLevelINFO, 0, "", "监听端口: %s", config.ListenPort)
	logMsg(config, LogLevelINFO, 0, "", "转发目标: %s", config.TargetAddr)
	if len(config.Whitelist) > 0 {
		logMsg(config, LogLevelINFO, 0, "", "SNI白名单: %s", config.WhitelistStr)
	} else {
		logMsg(config, LogLevelINFO, 0, "", "SNI白名单: 未设置 (允许所有)")
	}
	if config.Debug {
		logMsg(config, LogLevelINFO, 0, "", "调试模式: 已启用")
	}
	logMsg(config, LogLevelINFO, 0, "", "等待连接...")

	connID := 0

	// 用于接受连接
	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					logMsg(config, LogLevelERROR, 0, "", "接受连接失败: %v", err)
					continue
				}
			}

			connID++
			go handleConnection(clientConn, config, connID)
		}
	}()

	// 等待停止信号
	<-stopCh
	logMsg(config, LogLevelINFO, 0, "", "服务正在停止...")
}

func main() {
	var serviceCmd string
	flag.StringVar(&serviceCmd, "service", "", "服务命令: install, uninstall, start, stop")

	config := &Config{
		Whitelist: make(map[string]bool),
	}

	// 命令行参数
	flag.StringVar(&config.ListenPort, "listen", ":3389", "监听端口")
	flag.StringVar(&config.TargetAddr, "target", "", "目标地址")
	flag.StringVar(&config.WhitelistStr, "sni", "", "SNI白名单，逗号分隔")
	flag.BoolVar(&config.Debug, "debug", false, "调试模式（显示详细数据包信息）")
	flag.Parse()

	// 处理服务命令
	if serviceCmd != "" {
		err := handleServiceCommand(serviceCmd)
		if err != nil {
			log.Fatalf("服务命令执行失败: %v", err)
		}
		return
	}

	if config.TargetAddr == "" {
		log.Fatal("必须指定 -target 参数")
	}

	// 解析白名单
	if config.WhitelistStr != "" {
		for _, sni := range strings.Split(config.WhitelistStr, ",") {
			sni = strings.TrimSpace(sni)
			if sni != "" {
				config.Whitelist[sni] = true
			}
		}
	}

	// 检查是否作为Windows服务运行
	if isWindowsService() {
		err := runAsService(config)
		if err != nil {
			log.Fatalf("运行服务失败: %v", err)
		}
		return
	}

	// 作为控制台程序运行
	stopCh := make(chan struct{})
	runServer(config, stopCh)
}

func handleServiceCommand(cmd string) error {
	switch cmd {
	case "install":
		exePath, err := getExecutablePath()
		if err != nil {
			return err
		}
		return installService(exePath)
	case "uninstall":
		return uninstallService()
	case "start":
		return startService()
	case "stop":
		return stopService()
	default:
		return fmt.Errorf("未知的服务命令: %s (可用命令: install, uninstall, start, stop)", cmd)
	}
}

func handleConnection(clientConn net.Conn, config *Config, connID int) {
	// 创建连接对象
	conn := NewConnection(config, connID, clientConn.RemoteAddr().String())
	conn.logDebug("新连接")

	// 连接到目标服务器
	targetConn, err := net.Dial("tcp", config.TargetAddr)
	if err != nil {
		conn.logError("连接目标失败: %v", err)
		clientConn.Close()
		return
	}

	conn.logDebug("已连接到目标 %s", config.TargetAddr)

	// 创建两个通道用于双向转发
	clientToServerDone := make(chan error, 1)
	serverToClientDone := make(chan error, 1)
	var closeOnce sync.Once

	// 客户端 -> 服务器
	go func() {
		var resultErr error
		buf := make([]byte, 4096)
		packetNum := 0
		var firstPacket []byte
		rdpNegotiated := false  // 是否检测到RDP协商包
		tlsDetected := false    // 是否检测到TLS升级

		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					resultErr = fmt.Errorf("客户端读取错误: %w", err)
				}
				break
			}

			packetNum++
			conn.logDebug("[包#%d] 客户端->服务器: %d 字节", packetNum, n)
			if config.Debug {
				fmt.Printf("  前%d字节: %02x\n", min(32, n), buf[:min(32, n)])
			}

			// 检查是否是TLS握手并提取SNI
			if n > 0 && buf[0] == 0x16 {
				conn.logDebug("✓ 检测到TLS握手包")
				tlsDetected = true

				// 保存这个包用于SNI提取
				firstPacket = make([]byte, n)
				copy(firstPacket, buf[:n])

				// 尝试提取SNI
				sni, err := extractSNI(firstPacket)
				if err == nil && sni != "" {
					conn.logInfo("[SNI] %s", sni)

					// 检查白名单（可以包含域名或IP地址）
					if len(config.Whitelist) > 0 {
						if !config.Whitelist[sni] {
							conn.logWarn("❌ SNI不在白名单中，断开连接")
							resultErr = ErrSNINotInWhitelist
							break
						}
						conn.logDebug("✓ SNI在白名单中")
					}
				} else if err != nil {
					conn.logDebug("⚠ TLS但未能提取SNI: %v", err)
				}
			} else if packetNum == 1 && buf[0] == 0x03 {
				conn.logDebug("→ RDP协议协商包 (等待TLS升级)")
				rdpNegotiated = true
			} else if rdpNegotiated && !tlsDetected && packetNum > 3 {
				// RDP协商后，超过3个包还没看到TLS升级
				if len(config.Whitelist) > 0 {
					conn.logWarn("❌ RDP协商后未检测到TLS升级，可能是绕过SNI检查，断开连接")
					resultErr = ErrSNINotInWhitelist
					break
				}
			}

			// 转发到服务器
			_, err = targetConn.Write(buf[:n])
			if err != nil {
				resultErr = fmt.Errorf("写入服务器错误: %w", err)
				break
			}
		}
		clientToServerDone <- resultErr
	}()

	// 服务器 -> 客户端
	go func() {
		var resultErr error
		buf := make([]byte, 4096)
		packetNum := 0
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					resultErr = fmt.Errorf("服务器读取错误: %w", err)
				}
				break
			}

			packetNum++
			conn.logDebug("[响应#%d] 服务器->客户端: %d 字节", packetNum, n)
			if config.Debug {
				fmt.Printf("  前%d字节: %02x\n", min(32, n), buf[:min(32, n)])
			}

			// 转发到客户端
			_, err = clientConn.Write(buf[:n])
			if err != nil {
				resultErr = fmt.Errorf("写入客户端错误: %w", err)
				break
			}
		}
		serverToClientDone <- resultErr
	}()

	// 等待任一方向结束
	var firstErr error
	select {
	case err := <-clientToServerDone:
		firstErr = err
	case err := <-serverToClientDone:
		firstErr = err
	}

	// 立即关闭两个连接,避免另一个goroutine继续读写已关闭的连接
	closeOnce.Do(func() {
		clientConn.Close()
		targetConn.Close()
	})

	// 等待另一个goroutine结束
	select {
	case <-clientToServerDone:
	case <-serverToClientDone:
	}

	// 只记录真实的错误(排除SNI白名单错误,因为已经记录为WARN)
	if firstErr != nil && !errors.Is(firstErr, ErrSNINotInWhitelist) {
		conn.logError("%v", firstErr)
	}

	conn.logDebug("连接关闭")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
