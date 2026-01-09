package v1

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yiran15/api-server/base/apitypes"
	"github.com/yiran15/api-server/base/constant"
	"github.com/yiran15/api-server/base/helper"
	"github.com/yiran15/api-server/base/log"
	"github.com/yiran15/api-server/model"
	"github.com/yiran15/api-server/pkg/jwt"
	localcache "github.com/yiran15/api-server/pkg/local_cache"
	"github.com/yiran15/api-server/pkg/oauth"
	"github.com/yiran15/api-server/store"
	"github.com/yiran15/api-server/stores"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserServicer interface {
	GeneralUserServicer
	OAuthServicer
}

type OAuthServicer interface {
	OAuth2Provider(ctx context.Context) ([]string, error)
	OAuth2Login(provider, state string) (string, error)
	OAuth2Callback(ctx context.Context, req *apitypes.OAuthLoginRequest) (*apitypes.UserLoginResponse, error)
	OAuth2Activate(ctx context.Context, req *apitypes.OAuthActivateRequest) (*apitypes.UserLoginResponse, error)
}

type GeneralUserServicer interface {
	Login(ctx context.Context, req *apitypes.UserLoginRequest) (*apitypes.UserLoginResponse, error)
	Logout(ctx context.Context) error
	Info(ctx context.Context) (*model.User, error)
	CreateUser(ctx context.Context, req *apitypes.UserCreateRequest) error
	UpdateUserByAdmin(ctx context.Context, req *apitypes.UserUpdateAdminRequest) error
	UpdateUserBySelf(ctx context.Context, req *apitypes.UserUpdateSelfRequest) error
	DeleteUser(ctx context.Context, req *apitypes.IDRequest) error
	QueryUser(ctx context.Context, req *apitypes.IDRequest) (*model.User, error)
	ListUser(ctx context.Context, pagination *apitypes.UserListRequest) (*apitypes.UserListResponse, error)
}

type UserService struct {
	userStore       store.UserStorer
	roleStore       store.RoleStorer
	cacheStore      store.CacheStorer
	feishuUserStore store.FeiShuUserStorer
	tx              store.TxManagerInterface
	jwt             jwt.JwtInterface
	oauth           *oauth.OAuth2
	localCache      localcache.Cacher
}

func NewUserService(userStore store.UserStorer, roleStore store.RoleStorer, cacheStore store.CacheStorer, tx store.TxManagerInterface, jwt jwt.JwtInterface, feishuOauth *oauth.OAuth2, feishuUserStore store.FeiShuUserStorer, localCache localcache.Cacher) UserServicer {
	return &UserService{
		userStore:       userStore,
		roleStore:       roleStore,
		cacheStore:      cacheStore,
		tx:              tx,
		jwt:             jwt,
		oauth:           feishuOauth,
		feishuUserStore: feishuUserStore,
		localCache:      localCache,
	}
}

func (self *UserService) Login(ctx context.Context, req *apitypes.UserLoginRequest) (*apitypes.UserLoginResponse, error) {
	u := stores.User
	user, err := u.WithContext(ctx).Where(u.Email.Eq(req.Email), u.Status.Eq(1)).Preload(u.Roles).First()
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		log.WithRequestID(ctx).
			Error("login failed", zap.String("email", req.Email), zap.Error(constant.ErrUserNotFound))
		return nil, constant.ErrLoginFailed
	}

	if !self.checkPasswordHash(req.Password, user.Password) {
		log.WithRequestID(ctx).
			Error("login failed", zap.String("email", req.Email), zap.Error(constant.ErrPasswordWrong))
		return nil, constant.ErrLoginFailed
	}
	token, err := self.jwt.GenerateToken(user.ID, user.Name)
	if err != nil {
		return nil, err
	}

	tokenExpire := self.jwt.GetExpire()
	if len(user.Roles) == 0 {
		if err := self.cacheStore.SetSet(ctx, store.RoleType, user.ID, []any{constant.EmptyRoleSentinel}, &tokenExpire); err != nil {
			log.WithRequestID(ctx).
				Error("login set empty role cache error", zap.Int64("userID", user.ID), zap.Error(err))
		}
	} else {
		roleNames := make([]any, 0, len(user.Roles))
		for _, role := range user.Roles {
			roleNames = append(roleNames, role.Name)
		}
		if err := self.cacheStore.SetSet(ctx, store.RoleType, user.ID, roleNames, &tokenExpire); err != nil {
			log.WithRequestID(ctx).
				Error("login set role cache error", zap.Int64("userID", user.ID), zap.Any("roles", roleNames), zap.Error(err))
		}
	}

	return &apitypes.UserLoginResponse{
		User:  user,
		Token: token,
	}, nil
}

func (self *UserService) Logout(ctx context.Context) error {
	mc, err := self.jwt.GetUser(ctx)
	if err != nil {
		return err
	}
	return self.cacheStore.DelKey(ctx, store.RoleType, mc.UserID)
}

func (self *UserService) CreateUser(ctx context.Context, req *apitypes.UserCreateRequest) error {
	var (
		u     = stores.User
		r     = stores.Role
		user  *model.User
		err   error
		total int64
		roles []*model.Role
	)

	if req.RolesID != nil {
		*req.RolesID = helper.RemoveDuplicates(*req.RolesID)
	}

	if user, err = u.WithContext(ctx).Where(u.Email.Eq(req.Email), u.Status.Eq(1)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}

	if user != nil {
		return fmt.Errorf("user %s already exists", req.Name)
	}

	hashedPassword, err := self.hashPassword(req.Password)
	if err != nil {
		return err
	}

	if req.RolesID != nil {
		if total, err = r.WithContext(ctx).Where(r.ID.In(*req.RolesID...)).Count(); err != nil {
			return err
		}
		if roles, err = r.WithContext(ctx).Where(r.ID.In(*req.RolesID...)).Find(); err != nil {
			return err
		}
		if err = helper.ValidateRoleIds(*req.RolesID, roles, total); err != nil {
			return err
		}
	}

	user = &model.User{
		Name:     req.Name,
		NickName: req.NickName,
		Email:    req.Email,
		Password: hashedPassword,
		Avatar:   req.Avatar,
		Mobile:   req.Mobile,
		Roles:    roles,
	}

	return u.WithContext(ctx).Create(user)
}

func (self *UserService) UpdateUserByAdmin(ctx context.Context, req *apitypes.UserUpdateAdminRequest) error {
	if err := self.updateUser(ctx, nil, req); err != nil {
		return err
	}

	if req.RolesID == nil {
		return nil
	}

	return self.updateRole(ctx, &apitypes.UserUpdateRoleRequest{
		ID:      req.ID,
		RolesID: *req.RolesID,
	})
}

func (self *UserService) UpdateUserBySelf(ctx context.Context, req *apitypes.UserUpdateSelfRequest) error {
	mc, err := self.jwt.GetUser(ctx)
	if err != nil {
		return err
	}
	user, err := self.userStore.Query(ctx, store.Where("id", mc.UserID))
	if err != nil {
		return err
	}
	if req.OldPassword == "" {
		return errors.New("old password is required")
	}
	if !self.checkPasswordHash(req.OldPassword, user.Password) {
		return errors.New("invalid old password")
	}
	newReq := new(apitypes.UserUpdateAdminRequest)
	newReq.ID = mc.UserID
	newReq.UserUpdateSelfRequest = req
	return self.updateUser(ctx, user, newReq)
}

func (self *UserService) DeleteUser(ctx context.Context, req *apitypes.IDRequest) error {
	user, err := self.userStore.Query(ctx, store.Where("id", req.ID))
	if err != nil {
		return err
	}
	if err := self.userStore.Delete(ctx, user); err != nil {
		return err
	}

	feishuUser, err := self.feishuUserStore.Query(ctx, store.Where("user_id", req.ID))
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}
	if feishuUser != nil {
		if err := self.feishuUserStore.Delete(ctx, feishuUser); err != nil {
			return err
		}
	}

	return self.userStore.ClearAssociation(ctx, user, model.PreloadRoles)
}

func (self *UserService) QueryUser(ctx context.Context, req *apitypes.IDRequest) (*model.User, error) {
	return self.userStore.Query(ctx, store.Where("id", req.ID), store.Preload(model.PreloadRoles))
}

func (self *UserService) Info(ctx context.Context) (*model.User, error) {
	mc, err := self.jwt.GetUser(ctx)
	if err != nil {
		return nil, err
	}
	if mc.UserID == 0 {
		log.WithRequestID(ctx).Error("user not found", zap.Int64("userId", mc.UserID), zap.String("userName", mc.UserName))
		return nil, errors.New("user not found")
	}
	return self.userStore.Query(ctx, store.Where("id", mc.UserID), store.Preload(model.PreloadRoles))
}

func (self *UserService) ListUser(ctx context.Context, req *apitypes.UserListRequest) (*apitypes.UserListResponse, error) {
	var (
		likeOpt   store.Option
		statusOpt store.Option
		filed     = "id"
		oder      = "desc"
	)

	if req.Name != "" {
		likeOpt = store.Like("name", req.Name+"%")
	} else if req.Email != "" {
		likeOpt = store.Like("email", req.Email+"%")
	} else if req.Mobile != "" {
		likeOpt = store.Like("mobile", req.Mobile+"%")
	} else if req.Department != "" {
		likeOpt = store.Like("department", req.Department+"%")
	}

	if req.Status != 0 {
		statusOpt = store.Where("status", req.Status)
	}

	if req.Sort != "" && req.Direction != "" {
		filed = req.Sort
		oder = req.Direction
	}

	total, objs, err := self.userStore.List(ctx, req.Page, req.PageSize, filed, oder, likeOpt, statusOpt)
	if err != nil {
		return nil, err
	}
	res := &apitypes.UserListResponse{
		ListResponse: &apitypes.ListResponse{
			Pagination: &apitypes.Pagination{
				Page:     req.Page,
				PageSize: req.PageSize,
			},
			Total: total,
		},
		List: objs,
	}
	return res, nil
}

func (self *UserService) updateUser(ctx context.Context, user *model.User, req *apitypes.UserUpdateAdminRequest) error {
	var err error
	if user == nil {
		user, err = self.userStore.Query(ctx, store.Where("id", req.ID))
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("user %d not found", req.ID)
			}
			return err
		}
	}

	if req.UserUpdateSelfRequest != nil {
		user.Name = req.UserUpdateSelfRequest.Name
		user.NickName = req.UserUpdateSelfRequest.NickName
		user.Email = req.UserUpdateSelfRequest.Email
		user.Avatar = req.UserUpdateSelfRequest.Avatar
		user.Mobile = req.UserUpdateSelfRequest.Mobile
		if req.Password != "" {
			hashedPassword, err := self.hashPassword(req.Password)
			if err != nil {
				return err
			}
			user.Password = hashedPassword
		}
	}

	if req.Status != 0 {
		user.Status = &req.Status
	}
	return self.userStore.Update(ctx, user)
}

func (self *UserService) updateRole(ctx context.Context, req *apitypes.UserUpdateRoleRequest) error {
	var (
		total int64
		err   error
		roles []*model.Role
	)
	req.RolesID = helper.RemoveDuplicates(req.RolesID)
	user, err := self.userStore.Query(ctx, store.Where("id", req.ID), store.Preload(model.PreloadRoles))
	if err != nil {
		return err
	}

	total, roles, err = self.roleStore.List(ctx, 0, 0, "", "", store.In("id", req.RolesID))
	if err != nil {
		return err
	}

	if err = helper.ValidateRoleIds(req.RolesID, roles, total); err != nil {
		return err
	}

	if err := self.userStore.ReplaceAssociation(ctx, user, model.PreloadRoles, roles); err != nil {
		return err
	}

	// 如果redis缓存中存在该用户的角色，需要删除
	cacheRoles, err := self.cacheStore.GetSet(ctx, store.RoleType, user.ID)
	if err != nil {
		return err
	}

	// 如果未找到缓存，直接返回
	if len(cacheRoles) == 0 {
		return nil
	}

	if err := self.cacheStore.DelKey(ctx, store.RoleType, user.ID); err != nil {
		return err
	}

	roleNames := make([]any, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	go func() {
		time.Sleep(time.Second * 5)
		if err := self.cacheStore.DelKey(context.TODO(), store.RoleType, user.ID); err != nil {
			log.WithRequestID(ctx).Error("del role cache error", zap.Int64("userID", user.ID), zap.Any("roleNames", roleNames), zap.Error(err))
			return
		}
		log.WithRequestID(ctx).Info("del role cache success", zap.Int64("userID", user.ID), zap.Any("roleNames", roleNames))
	}()

	return self.cacheStore.SetSet(ctx, store.RoleType, user.ID, roleNames, nil)
}

// hashPassword 对密码进行 Bcrypt 哈希
func (self *UserService) hashPassword(password string) (string, error) {
	// bcrypt.DefaultCost 是一个合理的默认值，如果需要更高的安全性可以增加
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// checkPasswordHash 验证明文密码是否与哈希密码匹配
func (self *UserService) checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // 如果没有错误，则匹配成功
}

func (self *UserService) OAuth2Login(provider, state string) (string, error) {
	return self.oauth.Redirect(state, provider), nil
}

func (self *UserService) OAuth2Callback(ctx context.Context, req *apitypes.OAuthLoginRequest) (*apitypes.UserLoginResponse, error) {
	var (
		userID   int64
		userName string
		roles    []*model.Role
		user     *model.User
	)
	provider, ok := ctx.Value(constant.ProviderContextKey).(string)
	if !ok {
		return nil, errors.New("invalid provider")
	}

	oauthToken, err := self.oauth.Auth(ctx, req.Code, provider)
	if err != nil {
		return nil, err
	}

	userInfo, err := self.oauth.UserInfo(ctx, oauthToken, provider)
	if err != nil {
		return nil, err
	}

	switch v := userInfo.(type) {
	case *model.FeiShuUser:
		feishuUser, err := self.feishuLogin(ctx, v)
		if err != nil {
			return nil, err
		}
		if feishuUser == nil || feishuUser.User == nil {
			return nil, errors.New("feishu user not found after login")
		}
		user = feishuUser.User
		userID = user.ID
		userName = user.Name
		roles = user.Roles
		if user.Status != nil && *user.Status != model.UserStatusActive {
			return &apitypes.UserLoginResponse{User: user, Token: ""}, nil
		}

	case *model.KeycloakUser:
		u, err := self.genericLogin(ctx, v)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, errors.New("generic user not found after login")
		}
		user = u
		userID = user.ID
		userName = user.Name
		roles = user.Roles
		if user.Status != nil && *user.Status != model.UserStatusActive {
			return &apitypes.UserLoginResponse{User: user, Token: ""}, nil
		}
	default:
		return nil, errors.New("unsupported oauth user type")
	}

	token, err := self.jwt.GenerateToken(userID, userName)
	if err != nil {
		return nil, err
	}

	roleNames := make([]any, 0, len(roles))
	if len(roles) > 0 {
		for _, r := range roles {
			if r == nil {
				continue
			}
			roleNames = append(roleNames, r.Name)
		}
	}

	if len(roleNames) > 0 {
		if err := self.cacheStore.SetSet(ctx, store.RoleType, userID, roleNames, nil); err != nil {
			log.WithRequestID(ctx).Error("login set role cache error", zap.Int64("userID", userID), zap.Any("roles", roleNames), zap.Error(err))
		}
	} else {
		// set a sentinel so other parts know user has no roles
		if err := self.cacheStore.SetSet(ctx, store.RoleType, userID, []any{constant.EmptyRoleSentinel}, nil); err != nil {
			log.WithRequestID(ctx).Error("login set empty role cache error", zap.Int64("userID", userID), zap.Error(err))
		}
	}

	return &apitypes.UserLoginResponse{User: user, Token: token}, nil
}

func (self *UserService) feishuLogin(ctx context.Context, userInfo *model.FeiShuUser) (*model.FeiShuUser, error) {
	if userInfo.UserID == "" {
		return nil, errors.New("feishu user is empty")
	}

	var email string
	if userInfo.EnterpriseEmail != "" {
		email = userInfo.EnterpriseEmail
	} else if userInfo.Email != "" {
		email = userInfo.Email
	}

	u := &model.User{
		Name:     userInfo.EnName,
		NickName: userInfo.EnName,
		Avatar:   userInfo.AvatarUrl,
		Mobile:   userInfo.Mobile,
		Status:   helper.Int(model.UserStatusInactive),
		Email:    email,
	}

	feishuUser, err := self.feishuUserStore.Query(ctx, store.Where("user_id", userInfo.UserID), store.Preload("User.Roles"))
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if feishuUser == nil {
			feishuUser = userInfo
		}
		if feishuUser.User == nil {
			feishuUser.User = u
		}
		if err := self.feishuUserStore.Create(ctx, feishuUser); err != nil {
			return nil, err
		}
		return feishuUser, nil
	}

	if feishuUser.User == nil {
		if err := self.userStore.Create(ctx, u); err != nil {
			return nil, err
		}
		feishuUser.User = u
	}

	return feishuUser, nil
}

func (self *UserService) genericLogin(ctx context.Context, userInfo *model.KeycloakUser) (data *model.User, err error) {
	if userInfo.Sub == "" {
		return nil, errors.New("generic user is empty")
	}

	data, err = self.userStore.Query(ctx, store.Where("email", userInfo.Email), store.Preload("Roles"))
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		data = &model.User{
			Name:       userInfo.PreferredUsername,
			NickName:   userInfo.FamilyName + userInfo.GivenName,
			Email:      userInfo.Email,
			Status:     helper.Int(model.UserStatusInactive),
			Department: strings.Join(userInfo.Group, ","),
		}
		if len(userInfo.Roles) > 0 {
			_, roles, err := self.roleStore.List(ctx, 0, 0, "", "", store.In("name", userInfo.Roles))
			if err != nil {
				return nil, err
			}
			data.Roles = roles
		}
		if err := self.userStore.Create(ctx, data); err != nil {
			return nil, err
		}
	}

	return data, nil
}

func (self *UserService) OAuth2Provider(_ context.Context) ([]string, error) {
	data, err := self.localCache.GetCache(constant.OAuth2ProviderList)
	if err != nil {
		return nil, err
	}
	list, ok := data.([]string)
	if !ok {
		return nil, errors.New("get oauth2 provider list error")
	}
	sort.Strings(list)
	return list, nil
}

func (self *UserService) OAuth2Activate(ctx context.Context, req *apitypes.OAuthActivateRequest) (*apitypes.UserLoginResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, errors.New("password not match")
	}

	user, err := self.userStore.Query(ctx, store.Where("id", req.ID))
	if err != nil {
		return nil, err
	}

	password, err := self.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password error: %v", err)
	}
	user.Password = password
	user.Status = helper.Int(model.UserStatusActive)
	if err := self.userStore.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("update user error: %v", err)
	}
	token, err := self.jwt.GenerateToken(user.ID, user.Name)
	if err != nil {
		return nil, err
	}
	return &apitypes.UserLoginResponse{User: user, Token: token}, nil
}
