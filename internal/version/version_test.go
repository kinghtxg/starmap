package version

import "testing"

func TestVersionDefaults(t *testing.T) {
	if Version == "" {
		t.Fatal("Version 不能为空")
	}
	// 语义化版本：至少 x.y.z
	if _, err := parseSemver(Version); err != nil {
		t.Fatalf("Version %q 不是合法的语义化版本: %v", Version, err)
	}
}

func TestFull(t *testing.T) {
	oldV, oldC := Version, Commit
	defer func() { Version, Commit = oldV, oldC }()

	Version, Commit = "1.0.0", "dev"
	if got := Full(); got != "1.0.0" {
		t.Fatalf("无提交号时 Full() 应只返回版本号，实际 %q", got)
	}

	Version, Commit = "1.0.0", "abc1234"
	if got := Full(); got != "1.0.0+abc1234" {
		t.Fatalf("Full() 应拼接提交号，实际 %q", got)
	}
}

// parseSemver 极简校验：MAJOR.MINOR.PATCH，全部为数字。
func parseSemver(v string) ([3]int, error) {
	var out [3]int
	part := 0
	start := 0
	seen := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == '.' {
			if i == start {
				return out, errInvalid(v)
			}
			n := 0
			for j := start; j < i; j++ {
				if v[j] < '0' || v[j] > '9' {
					return out, errInvalid(v)
				}
				n = n*10 + int(v[j]-'0')
			}
			if part > 2 {
				return out, errInvalid(v)
			}
			out[part] = n
			part++
			seen++
			start = i + 1
		}
	}
	if seen != 3 {
		return out, errInvalid(v)
	}
	return out, nil
}

type errInvalid string

func (e errInvalid) Error() string { return "非法版本号: " + string(e) }
