// seedports 往指定库里灌端口/站点数据，用于对真实进程做规模压测。
//
// 为什么需要它：站点页（V1.7）的数据全部来自 ports 表的派生视图，
// 而探针/流量只产生会话与主机，不产生"有 HTTP 响应的端口"。
// 没有这份数据，站点页在压测里永远是空的，"首页 40ms 还是 2s"根本测不出来。
//
//	go run ./test/seedports -db C:/tmp/sm.db -hosts 4000 -per-host 12
//
// 生成的数据刻意包含判据边界：已过期/即将到期/远期证书、自签、无标题、
// 只有 banner 的非站点端口——站点筛选用例正是靠这些边界区分对错。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"starmap/internal/model"
	"starmap/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "目标数据库路径（必填）")
	hosts := flag.Int("hosts", 2000, "主机数")
	perHost := flag.Int("per-host", 10, "每台主机的端口数")
	reset := flag.Bool("reset", false, "先清空 ports 表")
	batch := flag.Int("batch", 2000, "每批写入条数")
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -db")
		flag.Usage()
		os.Exit(2)
	}

	if *reset {
		// 直接删库（含 WAL 附属文件）而不是 DELETE FROM ports：
		// 压测要的是"从空库开始、只由 seed 决定内容"，残留的会话/事件
		// 会让站点页与统计对比失去可比性。
		if err := removeDB(*dbPath); err != nil {
			log.Fatalf("清空库失败: %v", err)
		}
		fmt.Println("已删除旧库")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	now := time.Now()
	// 端口谱：80/443/8080/8443 是 Web，其余是"服务不是站点"的对照。
	ports := []int{80, 443, 8080, 8443, 22, 3306, 3389, 1521, 6379, 9200, 8000, 8888}
	titles := []string{
		"综合办公平台", "物资管理系统", "人事管理系统", "财务共享中心",
		"统一身份认证", "公文流转", "视频会议", "运维堡垒机", "",
	}
	products := []string{"泛微 e-cology", "致远 A8", "nginx", "Apache", "Tomcat", "海康威视", "", ""}

	total := 0
	var buf []model.PortRecord
	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := st.UpsertPorts(buf); err != nil {
			log.Fatalf("批量写入失败（已写 %d 条）: %v", total, err)
		}
		total += len(buf)
		buf = buf[:0]
	}

	for h := 0; h < *hosts; h++ {
		// 10.a.b.c，/16 以内，贴近真实内网
		ip := fmt.Sprintf("10.%d.%d.%d", (h>>16)&0xFF, (h>>8)&0xFF, h&0xFF)
		n := *perHost
		if n > len(ports) {
			n = len(ports)
		}
		for i := 0; i < n; i++ {
			p := ports[i]
			rec := model.PortRecord{
				NodeKey:   "ip:" + ip,
				IP:        ip,
				Port:      p,
				Proto:     "tcp",
				State:     "open",
				Source:    model.PortSourceProbe,
				FirstSeen: now.Add(-time.Duration(int64(h%240)+1) * time.Hour),
				LastSeen:  now.Add(-time.Duration(int64(h%30)) * time.Minute),
			}
			isWeb := p == 80 || p == 443 || p == 8080 || p == 8443 || p == 8000 || p == 8888
			if isWeb {
				if h%10 != 0 { // 九成 Web 端口有应用层响应 → 是站点
					rec.HTTPStatus = 200
					rec.Title = titles[h%len(titles)]
					rec.Server = "nginx"
					rec.Product = products[h%len(products)]
				}
				if p == 443 || p == 8443 {
					rec.TLSCN = fmt.Sprintf("app%d.corp.local", h)
					rec.TLSNames = []string{rec.TLSCN}
					rec.CertIssuer = "Corp-CA"
					// 自签与到期状态用与 10 互质的周期，**不能复用 h%10**：
					// h%10 已经决定"是不是站点"了，再拿它决定证书状态的话，
					// 所有异常证书都会落在非站点主机上，站点页永远是
					// expiring=0 / expired=0 / self_signed=0 —— 等于没测。
					rec.SelfSigned = h%17 == 0
					switch {
					case h%13 == 0:
						rec.CertExpiry = now.AddDate(0, 0, -1-(h%30)).Format("2006-01-02")
					case h%13 <= 2:
						rec.CertExpiry = now.AddDate(0, 0, 1+(h%29)).Format("2006-01-02")
					default:
						rec.CertExpiry = now.AddDate(1, 0, 0).Format("2006-01-02")
					}
				}
			} else {
				rec.Service = map[int]string{22: "ssh", 3306: "mysql", 3389: "rdp", 1521: "oracle", 6379: "redis", 9200: "elasticsearch"}[p]
				rec.Banner = "banner-" + rec.Service
			}
			buf = append(buf, rec)
			if len(buf) >= *batch {
				flush()
			}
		}
	}
	flush()

	fmt.Printf("已写入 %d 条端口记录（%d 台主机 × 最多 %d 端口）\n", total, *hosts, *perHost)
}

// removeDB 删掉库文件与 WAL 附属文件（不存在则忽略）。
func removeDB(path string) error {
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
