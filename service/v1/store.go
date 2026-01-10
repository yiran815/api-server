package v1

import "github.com/yiran15/api-server/stores"

var (
	u = stores.User
	r = stores.Role
	f = stores.FeiShuUser
	a = stores.Api
	c = stores.CasbinRule
)

func NewStore() {
	u = stores.User
	r = stores.Role
	f = stores.FeiShuUser
	a = stores.Api
	c = stores.CasbinRule
}
