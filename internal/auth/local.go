package auth

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// verifyLocal 校验本地账号（bcrypt）。
// 账号不存在时也执行一次同等开销的 bcrypt 比对，避免通过响应时间枚举用户名。
func (r *runtime) verifyLocal(username, password string) (LocalUser, bool) {
	for _, u := range r.cfg.LocalUsers {
		if u.Username != username {
			continue
		}
		if u.PasswordBcrypt == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordBcrypt), []byte(password)) == nil {
			return u, true
		}
		return LocalUser{}, false
	}
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash()), []byte(password))
	return LocalUser{}, false
}

var (
	dummyOnce sync.Once
	dummyVal  string
)

// dummyHash 返回一个固定 bcrypt 散列，仅用于对齐失败路径耗时。
func dummyHash() string {
	dummyOnce.Do(func() {
		// "$2a$10$" + 固定盐值的散列，内容为不可猜的随机串；生成失败时退化为常量串。
		h, err := HashPassword("starmap-auth-dummy-password-" + randomHex(8))
		if err != nil {
			dummyVal = "$2a$10$0000000000000000000000000000000000000000000000000000"
			return
		}
		dummyVal = h
	})
	return dummyVal
}
