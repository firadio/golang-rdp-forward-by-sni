//go:build !windows
// +build !windows

package main

import (
	"fmt"
)

// 非Windows平台的存根函数

func runAsService(config *Config) error {
	return fmt.Errorf("Windows服务功能仅在Windows平台可用")
}

func installService(exePath string, configFile string, config *Config) error {
	return fmt.Errorf("Windows服务功能仅在Windows平台可用")
}

func uninstallService() error {
	return fmt.Errorf("Windows服务功能仅在Windows平台可用")
}

func startService() error {
	return fmt.Errorf("Windows服务功能仅在Windows平台可用")
}

func stopService() error {
	return fmt.Errorf("Windows服务功能仅在Windows平台可用")
}

func isWindowsService() bool {
	return false
}

func getExecutablePath() (string, error) {
	return "", fmt.Errorf("此功能仅在Windows平台可用")
}
