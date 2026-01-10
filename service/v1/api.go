package v1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yiran15/api-server/base/helper"
	"github.com/yiran15/api-server/base/log"
	"github.com/yiran15/api-server/base/types"
	"github.com/yiran15/api-server/model"
	"github.com/yiran15/api-server/store"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ApiServicer interface {
	CreateApi(ctx context.Context, req *types.ApiCreateRequest) error
	UpdateApi(ctx context.Context, req *types.ApiUpdateRequest) error
	DeleteApi(ctx context.Context, req *types.IDRequest) error
	QueryApi(ctx context.Context, req *types.IDRequest) (*model.Api, error)
	ListApi(ctx context.Context, pagination *types.ApiListRequest) (*types.ApiListResponse, error)
}

type ApiService struct{}

func NewApiServicer(apiStore store.ApiStorer) ApiServicer {
	return &ApiService{}
}

func (receiver *ApiService) CreateApi(ctx context.Context, req *types.ApiCreateRequest) (err error) {
	sql := a.WithContext(ctx)
	if _, err = sql.Where(a.Name.Eq(req.Name)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}

	if err = sql.Create(types.NewApi(req)); err != nil {
		return err
	}
	return nil
}

func (receiver *ApiService) UpdateApi(ctx context.Context, req *types.ApiUpdateRequest) (err error) {
	var (
		api *model.Api
		sql = a.WithContext(ctx).Where(a.ID.Eq(req.ID))
	)
	if api, err = sql.First(); err != nil {
		return err
	}
	api.Description = req.Description
	if _, err = sql.Updates(api); err != nil {
		return err
	}
	return nil
}

func (receiver *ApiService) DeleteApi(ctx context.Context, req *types.IDRequest) (err error) {
	var (
		api *model.Api
		sql = a.WithContext(ctx).Where(a.ID.Eq(req.ID))
	)

	if api, err = sql.Preload(a.Roles).First(); err != nil {
		return err
	}

	if len(api.Roles) > 0 {
		roles := make([]string, 0, len(api.Roles))
		for _, role := range api.Roles {
			roles = append(roles, role.Name)
		}
		rolesName := strings.Join(roles, ",")
		log.WithRequestID(ctx).Error("api has roles", zap.String("apiName", api.Name), zap.String("rolesName", rolesName))
		return fmt.Errorf("api %s has roles %s", api.Name, rolesName)
	}

	if _, err = sql.Delete(api); err != nil {
		return err
	}
	return nil
}

func (receiver *ApiService) QueryApi(ctx context.Context, req *types.IDRequest) (api *model.Api, err error) {
	if api, err = a.WithContext(ctx).Where(a.ID.Eq(req.ID)).First(); err != nil {
		return nil, err
	}
	return api, nil
}

func (receiver *ApiService) ListApi(ctx context.Context, req *types.ApiListRequest) (res *types.ApiListResponse, err error) {
	var (
		apis  []*model.Api
		total int64
		sql   = a.WithContext(ctx)
	)

	if req.Name != "" {
		sql = sql.Where(a.Name.Like(req.Name + "%"))
	} else if req.Path != "" {
		sql = sql.Where(a.Path.Like(req.Path + "%"))
	} else if req.Method != "" {
		sql = sql.Where(a.Method.Like(req.Method + "%"))
	}

	if total, err = sql.Count(); err != nil {
		return nil, err
	}

	if req.Sort != "" && req.Direction != "" {
		sort, ok := a.GetFieldByName(req.Sort)
		if !ok {
			return nil, fmt.Errorf("invalid sort field: %s", req.Sort)
		}
		sql = sql.Order(helper.Sort(sort, req.Direction))
	}

	if apis, err = sql.Limit(req.PageSize).Offset(req.Page - 1*req.PageSize).Find(); err != nil {
		return nil, err
	}

	return types.NewApiListResponse(apis, total, req.PageSize, req.Page), nil
}
