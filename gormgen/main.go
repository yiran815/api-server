package main

import (
	"github.com/yiran15/api-server/base/conf"
	"github.com/yiran15/api-server/base/data"
	"github.com/yiran15/api-server/model"
	"gorm.io/gen"
)

func main() {
	g := gen.NewGenerator(gen.Config{
		OutPath: "./stores",
		Mode:    gen.WithoutContext | gen.WithDefaultQuery | gen.WithQueryInterface,
	})
	conf.LoadConfig("./config.yaml")
	db, clear, err := data.NewDB()
	if err != nil {
		panic(err)
	}
	defer clear()
	g.UseDB(db)
	g.ApplyBasic(model.User{}, model.Role{}, model.Api{}, model.CasbinRule{}, model.OauthUser{})
	g.ApplyInterface(model.User{}, model.Role{}, model.Api{}, model.CasbinRule{}, model.OauthUser{})
	g.Execute()
}
