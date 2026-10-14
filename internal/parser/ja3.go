// JA3 / JA3S 指纹计算。
// 算法：MD5("version,ciphers,extensions,curves,point_formats")，
// 各字段以 "-" 连接十进制数值，GREASE 值需剔除。
package parser

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// isGREASE 判断是否为 GREASE 值（0x?A?A，高字节==低字节且低半字节为 0xA）。
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// joinUint16 以 "-" 连接十进制数值，跳过 GREASE 值。
func joinUint16(vals []uint16) string {
	var sb strings.Builder
	first := true
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		if !first {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
		first = false
	}
	return sb.String()
}

func joinByte(vals []byte) string {
	var sb strings.Builder
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	return sb.String()
}

// JA3String 生成 JA3 指纹字符串。
func JA3String(version uint16, ciphers, extensions, curves []uint16, pointFormats []byte) string {
	return strconv.Itoa(int(version)) + "," + joinUint16(ciphers) + "," +
		joinUint16(extensions) + "," + joinUint16(curves) + "," + joinByte(pointFormats)
}

// JA3 计算 ClientHello 的 JA3 哈希（MD5 十六进制）。
func JA3(version uint16, ciphers, extensions, curves []uint16, pointFormats []byte) string {
	sum := md5.Sum([]byte(JA3String(version, ciphers, extensions, curves, pointFormats)))
	return hex.EncodeToString(sum[:])
}

// JA3SString 生成 ServerHello 的 JA3S 指纹字符串（version,cipher,extensions）。
func JA3SString(version, cipher uint16, extensions []uint16) string {
	return strconv.Itoa(int(version)) + "," + strconv.Itoa(int(cipher)) + "," + joinUint16(extensions)
}

// JA3S 计算 ServerHello 的 JA3S 哈希。
func JA3S(version, cipher uint16, extensions []uint16) string {
	sum := md5.Sum([]byte(JA3SString(version, cipher, extensions)))
	return hex.EncodeToString(sum[:])
}
