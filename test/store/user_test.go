package store_test

import (
	"testing"

	"github.com/yiran15/api-server/model"
)

func TestCreateTable(t *testing.T) {
	if err := db.AutoMigrate(&model.Oauth2User{}); err != nil {
		t.Fatalf("failed to create table: %v", err)
	}
}
