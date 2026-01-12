package v1

import (
	"github.com/yiran15/api-server/store"
)

var (
	u      = store.User
	r      = store.Role
	a      = store.Api
	c      = store.CasbinRule
	oauth2 = store.Oauth2User
)

func NewStore() {
	u = store.User
	r = store.Role
	a = store.Api
	c = store.CasbinRule
	oauth2 = store.Oauth2User
}
