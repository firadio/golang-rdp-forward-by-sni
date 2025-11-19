//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "RDPForwardBySNI"
const serviceDisplayName = "RDP Forward by SNI"
const serviceDesc = "基于SNI的RDP协议转发服务"

type rdpService struct {
	config *Config
	stopCh chan struct{}
}

func (s *rdpService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// 启动服务
	s.stopCh = make(chan struct{})
	go runServer(s.config, s.stopCh)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(s.stopCh)
				break loop
			default:
				// 未知命令
			}
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return
}

func runAsService(config *Config) error {
	// 在服务模式下，打开日志文件
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取程序路径: %v", err)
	}
	logDir := filepath.Dir(exePath)
	logPath := filepath.Join(logDir, "rdp-forward.log")

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("无法打开日志文件 %s: %v", logPath, err)
	}
	config.LogFile = logFile

	return svc.Run(serviceName, &rdpService{config: config})
}

func installService(exePath string, config *Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("无法连接到服务管理器: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("服务已经存在")
	}

	// 构建服务启动参数
	args := []string{
		"-listen", config.ListenPort,
		"-target", config.TargetAddr,
	}
	if config.SNIWhitelistStr != "" {
		args = append(args, "-sni", config.SNIWhitelistStr)
	}
	if config.ClientWhitelistStr != "" {
		args = append(args, "-client-whitelist", config.ClientWhitelistStr)
	}
	if config.Debug {
		args = append(args, "-debug")
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("创建服务失败: %v", err)
	}
	defer s.Close()

	fmt.Printf("服务 '%s' 安装成功\n", serviceDisplayName)
	fmt.Printf("启动参数: -listen %s -target %s", config.ListenPort, config.TargetAddr)
	if config.SNIWhitelistStr != "" {
		fmt.Printf(" -sni %s", config.SNIWhitelistStr)
	}
	if config.ClientWhitelistStr != "" {
		fmt.Printf(" -client-whitelist %s", config.ClientWhitelistStr)
	}
	if config.Debug {
		fmt.Printf(" -debug")
	}
	fmt.Println()

	// 显示日志文件位置
	logPath := filepath.Join(filepath.Dir(exePath), "rdp-forward.log")
	fmt.Printf("服务日志文件: %s\n", logPath)

	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("无法连接到服务管理器: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("打开服务失败: %v", err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("删除服务失败: %v", err)
	}

	fmt.Printf("服务 '%s' 卸载成功\n", serviceDisplayName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("无法连接到服务管理器: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("打开服务失败: %v", err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("启动服务失败: %v", err)
	}

	fmt.Printf("服务 '%s' 启动成功\n", serviceDisplayName)
	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("无法连接到服务管理器: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("打开服务失败: %v", err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("停止服务失败: %v", err)
	}

	timeout := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("停止服务超时")
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("查询服务状态失败: %v", err)
		}
	}

	fmt.Printf("服务 '%s' 停止成功\n", serviceDisplayName)
	return nil
}

func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

func getExecutablePath() (string, error) {
	return os.Executable()
}
