package config

import (
	"sync"

	"starmap/internal/auth"
	"starmap/internal/model"
)

// Box 是 model.SystemConfig 的并发安全容器。
//
// 为什么需要它：配置不再是"启动时读一次、之后只读"的静态数据——
// PUT /api/config 会在运行中改它，而读它的地方分布在两类完全不同的 goroutine 上：
//
//	HTTP handler（getConfig / captureStart / scanPorts / discover*）
//	后台周期任务（maintenanceLoop 的保留期清理）
//
// 此前这些读写都落在同一个 *model.SystemConfig 上，没有任何同步。
// 两个管理员同时 GET/PUT 配置，或清理任务恰好撞上保存，就是一个真实的数据竞争
// （-race 能抓到，生产上表现为读到"改了一半"的配置）。
//
// 这里的约定很简单：**任何字段都不允许在 Box 之外被改写**。
// 读一律 Get()（拿副本，改副本不影响本体），写一律 Update()（写锁内改副本、整体替换，
// 请求失败可以整体回滚）。副本对 slice 做深拷贝，避免副本与本体共享底层数组。
type Box struct {
	mu sync.RWMutex
	v  model.SystemConfig
}

// NewBox 用初始配置创建容器。零值可用。
func NewBox(v model.SystemConfig) *Box {
	return &Box{v: cloneConfig(v)}
}

// Get 返回当前配置的独立副本。
//
// nil 接收者返回零值配置而不是 panic：测试里经常不构造 Cfg，
// 让测试因为 nil 崩掉并不会暴露真正要测的东西。
func (b *Box) Get() model.SystemConfig {
	if b == nil {
		return model.SystemConfig{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return cloneConfig(b.v)
}

// Update 在写锁内把副本交给 fn 修改，成功后整体替换并返回新副本。
//
// fn 返回 error 时放弃本次修改（返回原配置），这样"改到一半才发现某个字段非法"
// 不会留下半套生效的新配置——这是调用方（PUT /api/config）最需要的语义。
func (b *Box) Update(fn func(*model.SystemConfig) error) (model.SystemConfig, error) {
	if b == nil {
		return model.SystemConfig{}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	work := cloneConfig(b.v)
	if err := fn(&work); err != nil {
		return cloneConfig(b.v), err
	}
	b.v = work
	return cloneConfig(work), nil
}

// Set 整体替换配置（用于启动时合并运行期配置后的回填）。
func (b *Box) Set(v model.SystemConfig) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.v = cloneConfig(v)
}

// cloneConfig 深拷贝配置中的引用类型字段。
//
// 只拷贝 slice / map 就够：结构体本身是值语义，其余都是标量。
// 漏掉某个 slice 的后果不是崩溃，而是副本与本体共享底层数组——
// 单方 append 尚可，一旦有人按下标改写元素就会穿透到本体，且极难复现。
func cloneConfig(v model.SystemConfig) model.SystemConfig {
	v.CaptureInterfaces = cloneSlice(v.CaptureInterfaces)
	v.CorsOrigins = cloneSlice(v.CorsOrigins)
	v.TrustedProxies = cloneSlice(v.TrustedProxies)
	v.AutoDiscoveryCIDRs = cloneSlice(v.AutoDiscoveryCIDRs)
	v.AutoDiscoveryExcludeCIDRs = cloneSlice(v.AutoDiscoveryExcludeCIDRs)
	v.DiscoverCIDRs = cloneSlice(v.DiscoverCIDRs)
	// auth.Config 内嵌在配置里，同样带 slice
	v.Auth.PublicPaths = cloneSlice(v.Auth.PublicPaths)
	v.Auth.OIDC.Scopes = cloneSlice(v.Auth.OIDC.Scopes)
	if v.Auth.LocalUsers != nil {
		users := make([]auth.LocalUser, len(v.Auth.LocalUsers))
		copy(users, v.Auth.LocalUsers)
		v.Auth.LocalUsers = users
	}
	return v
}

func cloneSlice(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
