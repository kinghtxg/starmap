package probe

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// MurmurHash3 x86 32-bit 与 Shodan 风格的 favicon hash。
//
// 为什么自己实现而不用第三方库：
// favicon hash 是资产测绘里最"好用"的关联键——同一套系统的资产（哪怕换 IP、换域名、
// 换端口）favicon 往往完全一致，是判定"账外资产其实是同一套系统"的硬证据。
// 它只需要 40 行代码，为此引入一个依赖不符合本项目单二进制的取向。

func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h := seed
	n := len(data) / 4 * 4
	for i := 0; i < n; i += 4 {
		k := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		k *= c1
		k = k<<15 | k>>17
		k *= c2

		h ^= k
		h = h<<13 | h>>19
		h = h*5 + 0xe6546b64
	}

	// 尾部不足 4 字节
	var k uint32
	tail := data[n:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = k<<15 | k>>17
		k *= c2
		h ^= k
	}

	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// faviconHash 计算 Shodan 兼容的 favicon 哈希：
// 对图标内容做 base64（每 76 字符换行，末尾也带换行），再取 mmh3 的有符号 32 位结果。
// 这个"每 76 字符换行"的细节必须严格一致，否则算出来的值和社区的指纹库对不上，等于白算。
func faviconHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	enc := base64.StdEncoding.EncodeToString(body)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/76 + 2)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	h := int32(murmur3_32([]byte(b.String()), 0))
	return strconv.FormatInt(int64(h), 10)
}
