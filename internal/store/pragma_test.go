package store

// PRAGMA 生效性守卫。
//
// 为什么值得单独写一条：DSN 里拼错了 pragma 名字、或者驱动不认某个参数时，
// **SQLite 不会报错，只会静默用默认值**。于是代码里写着
// `cache_size(-8192)`、实际跑的是默认 2MB 页缓存，症状是"站点页莫名其妙地慢"
// ——排查时看代码看不出来，因为代码是对的，错的是"没生效"。
//
// 这套取值是给站点/端口这类全表聚合查询用的：
//   - cache_size：默认 2MB 对"5 万行端口"等于没有缓存；
//   - mmap_size：进程级共享，不吃按连接计的缓存配额；
//   - temp_store=MEMORY：GROUP BY / ORDER BY 的临时 B 树别落盘。

import (
	"testing"
)

// TestPragmasEffective 断言 DSN 里配置的 pragma 真的生效了。
func TestPragmasEffective(t *testing.T) {
	st, err := Open(t.TempDir() + "/pragma.db")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	defer st.Close()

	// 字符串型
	wantStr := map[string]string{
		"journal_mode": "wal",
	}
	for name, want := range wantStr {
		var got string
		if err := st.db.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
			t.Fatalf("读 %s 失败: %v", name, err)
		}
		if got != want {
			t.Fatalf("PRAGMA %s = %q，期望 %q（DSN 里那条没生效）", name, got, want)
		}
	}

	// 整数型
	wantInt := map[string]int64{
		"busy_timeout": 10000,
		"cache_size":   -8192, // 负值表示 KB，即 8MB
		"temp_store":   2,     // 2 = MEMORY
		"synchronous":  1,     // 1 = NORMAL（WAL 下的推荐值）
	}
	for name, want := range wantInt {
		var got int64
		if err := st.db.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
			t.Fatalf("读 %s 失败: %v", name, err)
		}
		if got != want {
			t.Fatalf("PRAGMA %s = %d，期望 %d（DSN 里那条没生效）", name, got, want)
		}
	}

	// mmap_size：只在"驱动/平台不支持 mmap"时会退回 0，那种情况下站点视图
	// 的读放大问题会悄悄回来，所以这里硬比对而不是"大于 0 就算过"。
	const wantMmap = 268435456 // 256MB
	var mmap int64
	if err := st.db.QueryRow("PRAGMA mmap_size").Scan(&mmap); err != nil {
		t.Fatalf("读 mmap_size 失败: %v", err)
	}
	if mmap != wantMmap {
		t.Fatalf("PRAGMA mmap_size = %d，期望 %d；为 0 表示 mmap 未启用，"+
			"站点视图的全表聚合会退化成每次读盘", mmap, wantMmap)
	}
	t.Logf("mmap_size = %d", mmap)
}
