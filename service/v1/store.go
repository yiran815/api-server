package v1

import "github.com/yiran15/api-server/stores"

var (
	u      = stores.User
	r      = stores.Role
	f      = stores.OauthUser
	a      = stores.Api
	c      = stores.CasbinRule
	oauth2 = stores.Oauth2User
)

func NewStore() {
	u = stores.User
	r = stores.Role
	f = stores.OauthUser
	a = stores.Api
	c = stores.CasbinRule
	oauth2 = stores.Oauth2User
}
