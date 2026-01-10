package v1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yiran15/api-server/base/data"
	"github.com/yiran15/api-server/base/helper"
	"github.com/yiran15/api-server/base/types"
	"github.com/yiran15/api-server/model"
	"github.com/yiran15/api-server/pkg/casbin"
	"github.com/yiran15/api-server/stores"
	"gorm.io/gorm"
)

type RoleServicer interface {
	CreateRole(ctx context.Context, req *types.RoleCreateRequest) error
	UpdateRole(ctx context.Context, req *types.RoleUpdateRequest) error
	DeleteRole(ctx context.Context, req *types.IDRequest) error
	QueryRole(ctx context.Context, req *types.IDRequest) (*model.Role, error)
	ListRole(ctx context.Context, pagination *types.RoleListRequest) (*types.RoleListResponse, error)
}

type roleService struct {
	casbinManager casbin.CasbinManager
}

func NewRoleService(casbinManager casbin.CasbinManager) RoleServicer {
	return &roleService{casbinManager: casbinManager}
}

func (receiver *roleService) CreateRole(ctx context.Context, req *types.RoleCreateRequest) (err error) {
	req.Apis = helper.RemoveDuplicates(req.Apis)
	var (
		role  *model.Role
		apis  []*model.Api
		rules []*model.CasbinRule
		total int64
	)
	if role, err = r.WithContext(ctx).Where(r.Name.Eq(req.Name)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}

	if role != nil {
		return fmt.Errorf("role %s already exists", req.Name)
	}

	if len(req.Apis) > 0 {
		sql := a.WithContext(ctx).Where(a.ID.In(req.Apis...))
		if total, err = sql.Count(); err != nil {
			return err
		}
		if apis, err = sql.Find(); err != nil {
			return err
		}
		if err := helper.ValidateRoleApis(req.Apis, total, apis); err != nil {
			return err
		}
	}

	for _, api := range apis {
		rules = append(rules, &model.CasbinRule{
			PType: helper.String("p"),
			V0:    helper.String(req.Name),
			V1:    helper.String(api.Path),
			V2:    helper.String(api.Method),
		})
	}

	err = stores.Use(data.GetDB(ctx)).Transaction(func(tx *stores.Query) error {
		role := &model.Role{
			Name:        req.Name,
			Description: req.Description,
			Apis:        apis,
		}
		if err := tx.CasbinRule.WithContext(ctx).Create(rules...); err != nil {
			return err
		}

		err := tx.Role.WithContext(ctx).Create(role)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	return receiver.casbinManager.LoadPolicy()
}

func (receiver *roleService) UpdateRole(ctx context.Context, req *types.RoleUpdateRequest) (err error) {
	var (
		total       int64
		role        *model.Role
		apis        []*model.Api
		rules       []*model.CasbinRule
		casbinRules []*model.CasbinRule
	)
	req.Apis = helper.RemoveDuplicates(req.Apis)
	if role, err = r.WithContext(ctx).Where(r.ID.Eq(req.ID)).First(); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("role not found")
		}
		return err
	}

	role.Description = req.Description
	if len(req.Apis) > 0 {
		sql := a.WithContext(ctx).Where(a.ID.In(req.Apis...))
		if total, err = sql.Count(); err != nil {
			return err
		}
		if apis, err = sql.Find(); err != nil {
			return err
		}

		if err := helper.ValidateRoleApis(req.Apis, total, apis); err != nil {
			return err
		}
	}

	casbinSql := c.WithContext(ctx).Where(c.V0.Eq(role.Name))
	if total, err = casbinSql.Count(); err != nil {
		return err
	}
	if casbinRules, err = casbinSql.Find(); err != nil {
		return err
	}

	for _, api := range apis {
		rules = append(rules, &model.CasbinRule{
			PType: helper.String("p"),
			V0:    helper.String(role.Name),
			V1:    helper.String(api.Path),
			V2:    helper.String(api.Method),
		})
	}

	err = stores.Use(data.GetDB(ctx)).Transaction(func(tx *stores.Query) error {
		if _, err := tx.Role.WithContext(ctx).Where(r.ID.Eq(role.ID)).Updates(role); err != nil {
			return err
		}
		if total > 0 {
			if _, err := tx.CasbinRule.WithContext(ctx).Delete(casbinRules...); err != nil {
				return err
			}
		}
		if err := tx.Role.Apis.Model(role).Replace(apis...); err != nil {
			return err
		}
		if err := tx.CasbinRule.WithContext(ctx).Create(rules...); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	return receiver.casbinManager.LoadPolicy()
}

func (receiver *roleService) DeleteRole(ctx context.Context, req *types.IDRequest) (err error) {
	var (
		role        *model.Role
		casbinRules []*model.CasbinRule
	)
	if role, err = r.WithContext(ctx).Where(r.ID.Eq(req.ID)).First(); err != nil {
		return err
	}

	if len(role.Users) > 0 {
		unameArry := make([]string, 0, len(role.Users))
		for _, u := range role.Users {
			unameArry = append(unameArry, u.Name)
		}
		unames := strings.Join(unameArry, ",")
		return fmt.Errorf("the role is being used by the users %s", unames)
	}

	if casbinRules, err = c.WithContext(ctx).Where(c.V0.Eq(role.Name)).Find(); err != nil {
		return err
	}

	err = stores.Use(data.GetDB(ctx)).Transaction(func(tx *stores.Query) error {
		if _, err = tx.Role.WithContext(ctx).Delete(role); err != nil {
			return err
		}

		if err = tx.Role.Apis.Model(role).Clear(); err != nil {
			return err
		}

		if _, err = tx.CasbinRule.WithContext(ctx).Delete(casbinRules...); err != nil {
			return err
		}
		return nil
	})

	return receiver.casbinManager.LoadPolicy()
}

func (receiver *roleService) QueryRole(ctx context.Context, req *types.IDRequest) (role *model.Role, err error) {
	if role, err = r.WithContext(ctx).Where(r.ID.Eq(req.ID)).Preload(r.Apis).First(); err != nil {
		return nil, err
	}
	return role, nil
}

func (receiver *roleService) ListRole(ctx context.Context, req *types.RoleListRequest) (*types.RoleListResponse, error) {
	var (
		err   error
		total int64
		roles []*model.Role
		sql   = r.WithContext(ctx)
	)

	if req.Name != "" {
		sql = sql.Where(r.Name.Like(req.Name + "%"))
	}

	if total, err = sql.Count(); err != nil {
		return nil, err
	}

	if req.Sort != "" && req.Direction != "" {
		sort, ok := r.GetFieldByName(req.Sort)
		if !ok {
			return nil, fmt.Errorf("invalid sort field: %s", req.Sort)
		}
		sql = sql.Order(helper.Sort(sort, req.Direction))
	}

	if roles, err = sql.Limit(req.PageSize).Offset((req.Page - 1) * req.PageSize).Find(); err != nil {
		return nil, err
	}

	return types.NewRoleListResponse(roles, total, req.Page, req.PageSize), nil
}
