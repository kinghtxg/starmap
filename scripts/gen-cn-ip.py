#!/usr/bin/env python3
"""生成"中国大陆地址段"数据，供 internal/geo 嵌入（判断国外主机用）。

输入支持两种格式，自动识别：

1. CIDR 清单（推荐，体积小且完整）
       curl -sO https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
       python scripts/gen-cn-ip.py cn-aggregated.zone internal/geo/data

2. APNIC delegated 统计文件
       curl -sO https://ftp.apnic.net/stats/apnic/delegated-apnic-latest
       python scripts/gen-cn-ip.py delegated-apnic-latest internal/geo/data

⚠️ 用 APNIC 时务必确认文件下载完整（末行地址应接近 223.x）。APNIC 那两个
delegated 文件体积有几 MB，慢速网络下极易被截断——截断的表会把国内的
114.x / 180.x / 220.x 全判成"国外"，而红色误标是最伤信任的错误。
脚本会做完整性自检：若最大段 < 200.0.0.0 直接报错退出。

输出 internal/geo/data/cn_ipv4.txt：每行 "起始整数 结束整数"（含两端，相邻已合并），
运行时解析成有序区间二分查找，不引入第三方依赖。

IPv6：暂不覆盖（APNIC delegated 文件不含 ipv6 段）。geo 包对 IPv6 返回"未知"，
不做国外判定——宁可漏标，不误标。
"""
import sys
from datetime import date
from ipaddress import IPv4Address, IPv4Network


def parse_cidr_file(path):
    out = []
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#") or "|" in line:
            continue
        try:
            net = IPv4Network(line, strict=False)
        except ValueError:
            continue
        out.append((int(net.network_address), int(net.broadcast_address)))
    return out, "CIDR 清单"


def parse_apnic_file(path):
    out = []
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        if line.startswith("#"):
            continue
        p = line.rstrip("\n").split("|")
        if len(p) < 7 or p[1] != "CN" or p[2] != "ipv4":
            continue
        if p[6] not in ("allocated", "assigned"):
            continue
        try:
            start, count = int(IPv4Address(p[3])), int(p[4])
        except ValueError:
            continue
        out.append((start, start + count - 1))
    return out, "APNIC delegated"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], sys.argv[2]

    ranges, kind = parse_cidr_file(src)
    if not ranges:
        ranges, kind = parse_apnic_file(src)
    if not ranges:
        print("没有解析到任何 CN IPv4 段，检查输入文件格式", file=sys.stderr)
        return 1

    ranges.sort()
    merged = []
    for lo, hi in ranges:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))

    # 完整性自检：中国段覆盖到 223.x，最大段明显偏小说明文件被截断了
    top = merged[-1][1]
    if top < int(IPv4Address("200.0.0.0")):
        print(
            f"数据不完整：最大段结束于 {IPv4Address(top)}，正常应超过 200.0.0.0。"
            "文件很可能是被截断的下载，请重新获取。",
            file=sys.stderr,
        )
        return 1

    header = (
        f"# 中国大陆 IPv4 段（来源：{kind}，生成日期 {date.today().isoformat()}）\n"
        f"# 原始 {len(ranges)} 条，合并相邻后 {len(merged)} 段\n"
        "# 格式：起始整数 结束整数（含两端），按起始递增\n"
    )
    path = f"{outdir}/cn_ipv4.txt"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)
        for lo, hi in merged:
            f.write(f"{lo} {hi}\n")
    print(f"{kind}：原始 {len(ranges)} 条 → 合并 {len(merged)} 段，最大段 {IPv4Address(top)}，写入 {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
