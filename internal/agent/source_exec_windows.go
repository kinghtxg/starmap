//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"syscall"
)

// shellCommand 在 Windows 上构造 cmd.exe 调用，返回命令与"杀掉整棵进程树"的函数。
//
// 为什么不用 exec.Command("cmd", "/S", "/C", command)：
// os/exec 会按 Windows 参数规则把参数里的 " 转义成 \"，而 cmd.exe 不认这种转义。
// 实测 `type "C:\Some Dir\a.pcap"` 会被拆成一堆不存在的名字，cmd 直接报
// "文件名、目录名或卷标语法不正确"。接管整条命令行（SysProcAttr.CmdLine，
// 原样传给 CreateProcess）才能让 cmd 收到用户写的那串东西。
func shellCommand(command string) (*exec.Cmd, func()) {
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd.exe /S /C " + command}
	return cmd, func() {
		if cmd.Process == nil {
			return
		}
		// 只 Kill cmd.exe 不够：dumpcap/tshark 是它的子进程，会活下来继续抓包，
		// 下次再启动探针就是两个进程抢同一块网卡。
		tk := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
		if err := tk.Run(); err != nil {
			_ = cmd.Process.Kill()
		}
	}
}
