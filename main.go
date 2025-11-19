package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenPort         string
	TargetAddr         string
	SNIWhitelist       map[string]bool // SNI白名单（TLS连接的目标域名/IP）
	SNIWhitelistStr    string
	ClientWhitelist    map[string]bool // 客户端计算机名白名单（非TLS连接）
	ClientWhitelistStr string
	Debug              bool
	LogFilePath        string // 日志文件路径（用于追加模式写入）
}

// JSONConfig JSON配置文件结构
type JSONConfig struct {
	Listen          string   `json:"listen"`           // 监听地址
	Target          string   `json:"target"`           // 目标地址
	SNIWhitelist    []string `json:"sni_whitelist"`    // SNI白名单数组
	ClientWhitelist []string `json:"client_whitelist"` // 客户端白名单数组
	Debug           bool     `json:"debug"`            // 调试模式
	LogFile         string   `json:"log_file"`         // 日志文件路径
}

// 从JSON配置文件加载配置
func loadConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var jsonConfig JSONConfig
	if err := json.Unmarshal(data, &jsonConfig); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	config := &Config{
		SNIWhitelist:    make(map[string]bool),
		ClientWhitelist: make(map[string]bool),
		ListenPort:      jsonConfig.Listen,
		TargetAddr:      jsonConfig.Target,
		Debug:           jsonConfig.Debug,
		LogFilePath:     jsonConfig.LogFile,
	}

	// 处理SNI白名单
	if len(jsonConfig.SNIWhitelist) > 0 {
		config.SNIWhitelistStr = strings.Join(jsonConfig.SNIWhitelist, ",")
		for _, sni := range jsonConfig.SNIWhitelist {
			sni = strings.TrimSpace(sni)
			if sni != "" {
				config.SNIWhitelist[sni] = true
			}
		}
	}

	// 处理客户端白名单
	if len(jsonConfig.ClientWhitelist) > 0 {
		config.ClientWhitelistStr = strings.Join(jsonConfig.ClientWhitelist, ",")
		for _, client := range jsonConfig.ClientWhitelist {
			client = strings.TrimSpace(client)
			if client != "" {
				config.ClientWhitelist[client] = true
			}
		}
	}

	// 设置默认值
	if config.ListenPort == "" {
		config.ListenPort = ":3389"
	}

	return config, nil
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

	var logLine string
	if connID > 0 {
		if clientAddr != "" {
			logLine = fmt.Sprintf("[%s] [%s] [连接#%d,%s] %s\n", timestamp, level, connID, clientAddr, message)
		} else {
			logLine = fmt.Sprintf("[%s] [%s] [连接#%d] %s\n", timestamp, level, connID, message)
		}
	} else {
		logLine = fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, message)
	}

	// 输出到控制台
	fmt.Print(logLine)

	// 如果配置了日志文件路径，以追加模式写入文件
	if config.LogFilePath != "" {
		// 每次打开文件追加写入，然后关闭（避免文件被锁定）
		logFile, err := os.OpenFile(config.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			// Windows使用\r\n，其他系统使用\n
			if runtime.GOOS == "windows" {
				fileLogLine := logLine[:len(logLine)-1] + "\r\n"
				logFile.WriteString(fileLogLine)
			} else {
				logFile.WriteString(logLine)
			}
			logFile.Close()
		}
	}
}

// 尝试从RDP MCS Connect Initial中提取客户端信息（仅未加密连接）
func extractRDPClientInfo(data []byte) (clientName string, err error) {
	// MCS Connect Initial PDU的特征：
	// TPKT header (4 bytes): 03 00 length_hi length_lo
	// X.224 Data TPDU: length 02 f0 80
	// MCS Connect-Initial: 7f 65 ...

	if len(data) < 20 {
		return "", fmt.Errorf("data too short")
	}

	// 检查TPKT header
	if data[0] != 0x03 || data[1] != 0x00 {
		return "", fmt.Errorf("not a TPKT packet")
	}

	// 查找 MCS Connect-Initial (0x7f65) 或 Connect-Response
	// 简化实现：搜索 "clientName" 或常见的UTF-16编码的计算机名
	// 这只是一个启发式方法，不是完整的ASN.1解析

	// 在数据中搜索可能的计算机名（UTF-16编码的字符串）
	// 通常在偏移量100-500字节之间
	for i := 10; i < len(data)-20 && i < 600; i++ {
		// 查找UTF-16编码的字符串模式 (ASCII字符后跟0x00)
		if data[i] >= 0x20 && data[i] <= 0x7E && data[i+1] == 0x00 {
			// 可能找到了UTF-16字符串
			var name []byte
			for j := i; j < len(data)-1 && j < i+64; j += 2 {
				if data[j] == 0x00 && data[j+1] == 0x00 {
					// 字符串结束
					break
				}
				if data[j] >= 0x20 && data[j] <= 0x7E && data[j+1] == 0x00 {
					name = append(name, data[j])
				} else {
					break
				}
			}
			if len(name) > 3 { // 至少4个字符才认为是有效的计算机名
				return string(name), nil
			}
		}
	}

	return "", fmt.Errorf("client name not found")
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
	if len(config.SNIWhitelist) > 0 {
		logMsg(config, LogLevelINFO, 0, "", "SNI白名单（TLS目标域名/IP）: %s", config.SNIWhitelistStr)
	} else {
		logMsg(config, LogLevelINFO, 0, "", "SNI白名单: 未设置")
	}
	if len(config.ClientWhitelist) > 0 {
		logMsg(config, LogLevelINFO, 0, "", "客户端白名单（计算机名）: %s", config.ClientWhitelistStr)
	} else {
		logMsg(config, LogLevelINFO, 0, "", "客户端白名单: 未设置")
	}
	if len(config.SNIWhitelist) == 0 && len(config.ClientWhitelist) == 0 {
		logMsg(config, LogLevelINFO, 0, "", "访问控制: 允许所有连接")
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
	var configFile string
	var listenPort string
	var targetAddr string
	var sniWhitelistStr string
	var clientWhitelistStr string
	var debugMode bool

	flag.StringVar(&serviceCmd, "service", "", "服务命令: install, uninstall, start, stop")
	flag.StringVar(&configFile, "c", "", "配置文件路径（JSON格式）")
	flag.StringVar(&listenPort, "listen", "", "监听端口")
	flag.StringVar(&targetAddr, "target", "", "目标地址")
	flag.StringVar(&sniWhitelistStr, "sni", "", "SNI白名单（TLS连接的目标域名/IP），逗号分隔")
	flag.StringVar(&clientWhitelistStr, "client-whitelist", "", "客户端计算机名白名单（非TLS连接），逗号分隔")
	flag.BoolVar(&debugMode, "debug", false, "调试模式（显示详细数据包信息）")
	flag.Parse()

	var config *Config
	var err error

	// 1. 如果指定了配置文件，先从文件加载配置
	if configFile != "" {
		config, err = loadConfigFromFile(configFile)
		if err != nil {
			log.Fatalf("加载配置文件失败: %v", err)
		}
	} else {
		// 没有配置文件时，初始化空配置
		config = &Config{
			SNIWhitelist:    make(map[string]bool),
			ClientWhitelist: make(map[string]bool),
			ListenPort:      ":3389", // 默认值
		}
	}

	// 2. 命令行参数覆盖配置文件（如果指定了的话）
	if listenPort != "" {
		config.ListenPort = listenPort
	}
	if targetAddr != "" {
		config.TargetAddr = targetAddr
	}
	if debugMode {
		config.Debug = true
	}

	// 3. 处理命令行的白名单参数（会覆盖配置文件）
	if sniWhitelistStr != "" {
		config.SNIWhitelistStr = sniWhitelistStr
		config.SNIWhitelist = make(map[string]bool) // 清空配置文件的设置
		for _, sni := range strings.Split(sniWhitelistStr, ",") {
			sni = strings.TrimSpace(sni)
			if sni != "" {
				config.SNIWhitelist[sni] = true
			}
		}
	}

	if clientWhitelistStr != "" {
		config.ClientWhitelistStr = clientWhitelistStr
		config.ClientWhitelist = make(map[string]bool) // 清空配置文件的设置
		for _, client := range strings.Split(clientWhitelistStr, ",") {
			client = strings.TrimSpace(client)
			if client != "" {
				config.ClientWhitelist[client] = true
			}
		}
	}

	// 处理服务命令
	if serviceCmd != "" {
		err := handleServiceCommand(serviceCmd, config)
		if err != nil {
			log.Fatalf("服务命令执行失败: %v", err)
		}
		return
	}

	if config.TargetAddr == "" {
		log.Fatal("必须指定 -target 参数或配置文件")
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

func handleServiceCommand(cmd string, config *Config) error {
	switch cmd {
	case "install":
		exePath, err := getExecutablePath()
		if err != nil {
			return err
		}
		return installService(exePath, config)
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
		rdpNegotiated := false    // 是否检测到RDP协商包
		tlsDetected := false      // 是否检测到TLS升级
		clientIdentified := false // 是否已识别客户端（TLS的SNI或非TLS的客户端名）

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
					clientIdentified = true // 标记已识别客户端

					// 检查SNI白名单
					if len(config.SNIWhitelist) > 0 {
						if !config.SNIWhitelist[sni] {
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
			} else if rdpNegotiated && !tlsDetected {
				// 尝试从非TLS的RDP数据包中提取客户端信息
				if packetNum >= 2 && packetNum <= 5 {
					clientName, err := extractRDPClientInfo(buf[:n])
					if err == nil && clientName != "" {
						conn.logInfo("[RDP客户端] %s (未加密连接)", clientName)
						clientIdentified = true

						// 检查客户端白名单
						if len(config.ClientWhitelist) > 0 {
							if !config.ClientWhitelist[clientName] {
								conn.logWarn("❌ RDP客户端名称不在白名单中，断开连接")
								resultErr = ErrSNINotInWhitelist
								break
							}
							conn.logDebug("✓ RDP客户端名称在白名单中")
						}
					}
				}

				// 超过5个包还没检测到TLS也没找到客户端信息
				// 如果配置了SNI白名单，要求必须TLS；如果配置了客户端白名单，要求必须识别客户端
				if packetNum > 5 && !clientIdentified {
					if len(config.SNIWhitelist) > 0 {
						conn.logWarn("❌ RDP协商后未检测到TLS升级，配置了SNI白名单要求TLS连接，断开连接")
						resultErr = ErrSNINotInWhitelist
						break
					}
					if len(config.ClientWhitelist) > 0 {
						conn.logWarn("❌ 未能识别RDP客户端信息，配置了客户端白名单要求识别客户端，断开连接")
						resultErr = ErrSNINotInWhitelist
						break
					}
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
