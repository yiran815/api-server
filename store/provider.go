package store

import "github.com/google/wire"

var StoreProviderSet = wire.NewSet(
	wire.Bind(new(CacheStorer), new(*CacheStore)),
	NewCacheStore,
)
