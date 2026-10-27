//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// shellCommand 在类 Unix 上构造 sh -c 调用。
//
// 单独开一个进程组（Setpgid）然后杀整组：`sh -c "tcpdump ... | tee x"`
// 这种带管道的命令，只杀 sh 会留下一堆孤儿进程继续占着网卡。
func shellCommand(command string) (*exec.Cmd, func()) {
	cmd := exec.Command("sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, func() {
		if cmd.Process == nil {
			return
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			_ = cmd.Process.Kill()
		}
	}
}
