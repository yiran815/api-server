package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/yiran15/api-server/base/constant"
	"github.com/yiran15/api-server/base/data"
	"github.com/yiran15/api-server/base/helper"
	"github.com/yiran15/api-server/base/log"
	"github.com/yiran15/api-server/base/types"
	"github.com/yiran15/api-server/model"
	"github.com/yiran15/api-server/pkg/jwt"
	localcache "github.com/yiran15/api-server/pkg/local_cache"
	"github.com/yiran15/api-server/pkg/oauth"
	"github.com/yiran15/api-server/store"
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
	OAuth2Callback(ctx context.Context, req *types.OAuthLoginRequest) (*types.UserLoginResponse, error)
	OAuth2Activate(ctx context.Context, req *types.OAuthActivateRequest) (*types.UserLoginResponse, error)
}

type GeneralUserServicer interface {
	Login(ctx context.Context, req *types.UserLoginRequest) (*types.UserLoginResponse, error)
	Logout(ctx context.Context) error
	Info(ctx context.Context) (*model.User, error)
	CreateUser(ctx context.Context, req *types.UserCreateRequest) error
	UpdateUserByAdmin(ctx context.Context, req *types.UserUpdateAdminRequest) error
	UpdateUserBySelf(ctx context.Context, req *types.UserUpdateSelfRequest) error
	DeleteUser(ctx context.Context, req *types.IDRequest) error
	QueryUser(ctx context.Context, req *types.IDRequest) (*model.User, error)
	ListUser(ctx context.Context, pagination *types.UserListRequest) (*types.UserListResponse, error)
}

type UserService struct {
	cacheStore store.CacheStorer
	jwt        jwt.JwtInterface
	oauth      *oauth.OAuth2
	localCache localcache.Cacher
}

func NewUserService(cacheStore store.CacheStorer, jwt jwt.JwtInterface, feishuOauth *oauth.OAuth2, localCache localcache.Cacher) UserServicer {
	return &UserService{
		cacheStore: cacheStore,
		jwt:        jwt,
		oauth:      feishuOauth,
		localCache: localCache,
	}
}

func (receiver *UserService) Login(ctx context.Context, req *types.UserLoginRequest) (*types.UserLoginResponse, error) {
	user, err := u.WithContext(ctx).Where(u.Email.Eq(req.Email), u.Status.Eq(1)).Preload(u.Roles).First()
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		log.WithRequestID(ctx).
			Error("login failed", zap.String("email", req.Email), zap.Error(constant.ErrUserNotFound))
		return nil, constant.ErrLoginFailed
	}

	if !receiver.checkPasswordHash(req.Password, user.Password) {
		log.WithRequestID(ctx).
			Error("login failed", zap.String("email", req.Email), zap.Error(constant.ErrPasswordWrong))
		return nil, constant.ErrLoginFailed
	}
	token, err := receiver.jwt.GenerateToken(user.ID, user.Name)
	if err != nil {
		return nil, err
	}

	tokenExpire := receiver.jwt.GetExpire()
	if len(user.Roles) == 0 {
		if err := receiver.cacheStore.SetSet(ctx, store.RoleType, user.ID, []any{constant.EmptyRoleSentinel}, &tokenExpire); err != nil {
			log.WithRequestID(ctx).
				Error("login set empty role cache error", zap.Int64("userID", user.ID), zap.Error(err))
		}
	} else {
		roleNames := make([]any, 0, len(user.Roles))
		for _, role := range user.Roles {
			roleNames = append(roleNames, role.Name)
		}
		if err := receiver.cacheStore.SetSet(ctx, store.RoleType, user.ID, roleNames, &tokenExpire); err != nil {
			log.WithRequestID(ctx).
				Error("login set role cache error", zap.Int64("userID", user.ID), zap.Any("roles", roleNames), zap.Error(err))
		}
	}

	return types.NewUserLoginResponse(user, token), nil
}

func (receiver *UserService) Logout(ctx context.Context) error {
	mc, err := receiver.jwt.GetUser(ctx)
	if err != nil {
		return err
	}
	return receiver.cacheStore.DelKey(ctx, store.RoleType, mc.UserID)
}

func (receiver *UserService) CreateUser(ctx context.Context, req *types.UserCreateRequest) (err error) {
	var (
		user  *model.User
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

	hashedPassword, err := receiver.hashPassword(req.Password)
	if err != nil {
		return err
	}

	if req.RolesID != nil {
		if roles, err = r.WithContext(ctx).Where(r.ID.In(*req.RolesID...)).Find(); err != nil {
			return err
		}
		if err = helper.ValidateRoleIds(*req.RolesID, roles); err != nil {
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

func (receiver *UserService) UpdateUserByAdmin(ctx context.Context, req *types.UserUpdateAdminRequest) error {
	if err := receiver.updateUser(ctx, nil, req); err != nil {
		return err
	}

	if req.RolesID == nil {
		return nil
	}

	return receiver.updateRole(ctx, &types.UserUpdateRoleRequest{
		ID:      req.ID,
		RolesID: *req.RolesID,
	})
}

func (receiver *UserService) UpdateUserBySelf(ctx context.Context, req *types.UserUpdateSelfRequest) error {
	var (
		user *model.User
	)
	mc, err := receiver.jwt.GetUser(ctx)
	if err != nil {
		return err
	}

	if user, err = u.WithContext(ctx).Where(u.ID.Eq(mc.UserID)).First(); err != nil {
		return err
	}

	if req.OldPassword == "" {
		return errors.New("old password is required")
	}
	if !receiver.checkPasswordHash(req.OldPassword, user.Password) {
		return errors.New("invalid old password")
	}
	newReq := new(types.UserUpdateAdminRequest)
	newReq.ID = mc.UserID
	newReq.UserUpdateSelfRequest = req
	return receiver.updateUser(ctx, user, newReq)
}

func (receiver *UserService) DeleteUser(ctx context.Context, req *types.IDRequest) (err error) {
	var (
		user *model.User
	)
	return store.Use(data.GetDB(ctx)).Transaction(func(tx *store.Query) error {
		if user, err = tx.User.WithContext(ctx).Where(u.ID.Eq(req.ID)).Preload(u.Oauth2User).First(); err != nil {
			return err
		}
		if _, err := tx.User.WithContext(ctx).Delete(user); err != nil {
			return err
		}
		if _, err := tx.Oauth2User.WithContext(ctx).Delete(user.Oauth2User); err != nil {
			return err
		}
		return tx.User.Roles.WithContext(ctx).Model(user).Clear()
	})
}

func (receiver *UserService) QueryUser(ctx context.Context, req *types.IDRequest) (*model.User, error) {
	return u.WithContext(ctx).Where(u.ID.Eq(req.ID)).Preload(u.Roles).First()
}

func (receiver *UserService) Info(ctx context.Context) (*model.User, error) {
	mc, err := receiver.jwt.GetUser(ctx)
	if err != nil {
		return nil, err
	}
	if mc.UserID == 0 {
		log.WithRequestID(ctx).Error("user not found", zap.Int64("userId", mc.UserID), zap.String("userName", mc.UserName))
		return nil, errors.New("user not found")
	}
	return u.WithContext(ctx).Where(u.ID.Eq(mc.UserID)).Preload(u.Roles).First()
}

func (receiver *UserService) ListUser(ctx context.Context, req *types.UserListRequest) (*types.UserListResponse, error) {
	var (
		sql   = u.WithContext(ctx)
		users []*model.User
		err   error
		total int64
	)

	if req.Name != "" {
		sql = sql.Where(u.Name.Like(req.Name + "%"))
	} else if req.Email != "" {
		sql = sql.Where(u.Email.Like(req.Email + "%"))
	} else if req.Mobile != "" {
		sql = sql.Where(u.Mobile.Like(req.Mobile + "%"))
	} else if req.Department != "" {
		sql = sql.Where(u.Department.Like(req.Department + "%"))
	}

	if req.Status != 0 {
		sql = sql.Where(u.Status.Eq(req.Status))
	}

	if req.Sort != "" {
		orderCol, ok := u.GetFieldByName(req.Sort)
		if !ok {
			return nil, fmt.Errorf("invalid sort field: %s", req.Sort)
		}
		sql = sql.Order(helper.Sort(orderCol, req.Direction))
	}

	if total, err = sql.Count(); err != nil {
		return nil, err
	}
	if users, err = sql.Limit(req.PageSize).Offset((req.Page - 1) * req.PageSize).Find(); err != nil {
		return nil, err
	}

	res := &types.UserListResponse{
		ListResponse: &types.ListResponse{
			Pagination: &types.Pagination{
				Page:     req.Page,
				PageSize: req.PageSize,
			},
			Total: total,
		},
		List: users,
	}
	return res, nil
}

func (receiver *UserService) updateUser(ctx context.Context, user *model.User, req *types.UserUpdateAdminRequest) (err error) {
	if user == nil {
		if user, err = u.WithContext(ctx).Where(u.ID.Eq(req.ID)).First(); err != nil {
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
			hashedPassword, err := receiver.hashPassword(req.Password)
			if err != nil {
				return err
			}
			user.Password = hashedPassword
		}
	}

	if req.Status != 0 {
		user.Status = &req.Status
	}

	if _, err := u.WithContext(ctx).Where(u.ID.Eq(user.ID)).Updates(user); err != nil {
		return err
	}
	return nil
}

func (receiver *UserService) updateRole(ctx context.Context, req *types.UserUpdateRoleRequest) (err error) {
	var (
		roles []*model.Role
		user  *model.User
	)
	req.RolesID = helper.RemoveDuplicates(req.RolesID)
	if user, err = u.WithContext(ctx).Where(u.ID.Eq(req.ID)).Preload(u.Roles).First(); err != nil {
		return err
	}

	roleSql := r.WithContext(ctx).Where(r.ID.In(req.RolesID...))
	if roles, err = roleSql.Find(); err != nil {
		return err
	}

	if err = helper.ValidateRoleIds(req.RolesID, roles); err != nil {
		return err
	}
	if err = u.Roles.WithContext(ctx).Model(user).Replace(roles...); err != nil {
		return err
	}

	// 如果redis缓存中存在该用户的角色，需要删除
	cacheRoles, err := receiver.cacheStore.GetSet(ctx, store.RoleType, user.ID)
	if err != nil {
		return err
	}

	// 如果未找到缓存，直接返回
	if len(cacheRoles) == 0 {
		return nil
	}

	if err := receiver.cacheStore.DelKey(ctx, store.RoleType, user.ID); err != nil {
		return err
	}

	roleNames := make([]any, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	go func() {
		time.Sleep(time.Second * 5)
		if err := receiver.cacheStore.DelKey(context.TODO(), store.RoleType, user.ID); err != nil {
			log.WithRequestID(ctx).Error("del role cache error", zap.Int64("userID", user.ID), zap.Any("roleNames", roleNames), zap.Error(err))
			return
		}
		log.WithRequestID(ctx).Info("del role cache success", zap.Int64("userID", user.ID), zap.Any("roleNames", roleNames))
	}()

	return receiver.cacheStore.SetSet(ctx, store.RoleType, user.ID, roleNames, nil)
}

// hashPassword 对密码进行 Bcrypt 哈希
func (receiver *UserService) hashPassword(password string) (string, error) {
	// bcrypt.DefaultCost 是一个合理的默认值，如果需要更高的安全性可以增加
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// checkPasswordHash 验证明文密码是否与哈希密码匹配
func (receiver *UserService) checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // 如果没有错误，则匹配成功
}

func (receiver *UserService) OAuth2Login(provider, state string) (string, error) {
	return receiver.oauth.Redirect(state, provider), nil
}

func (receiver *UserService) OAuth2Callback(ctx context.Context, req *types.OAuthLoginRequest) (*types.UserLoginResponse, error) {
	var (
		oauth2User *model.Oauth2User
	)
	provider, ok := ctx.Value(constant.ProviderContextKey).(string)
	if !ok {
		return nil, errors.New("invalid provider")
	}
	_, ok = receiver.oauth.Providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported oauth2 provider: %s", provider)
	}

	oauthToken, err := receiver.oauth.Auth(ctx, req.Code, provider)
	if err != nil {
		return nil, err
	}

	userInfo, err := receiver.oauth.UserInfo(ctx, oauthToken, provider)
	if err != nil {
		return nil, err
	}

	if oauth2User, err = receiver.oauth2GetUser(ctx, provider, userInfo); err != nil {
		return nil, err
	}

	if *oauth2User.User.Status == model.UserStatusInactive {
		log.WithRequestID(ctx).Info("oauth2 user not activated", zap.Int64("userID", oauth2User.User.ID))
		return &types.UserLoginResponse{User: oauth2User.User, Token: ""}, nil
	}

	token, err := receiver.jwt.GenerateToken(oauth2User.User.ID, oauth2User.User.Name)
	if err != nil {
		return nil, err
	}

	roleNames := make([]any, 0, len(oauth2User.User.Roles))
	if len(oauth2User.User.Roles) > 0 {
		for _, r := range oauth2User.User.Roles {
			if r == nil {
				continue
			}
			roleNames = append(roleNames, r.Name)
		}
	}

	if len(roleNames) > 0 {
		if err := receiver.cacheStore.SetSet(ctx, store.RoleType, oauth2User.User.ID, roleNames, nil); err != nil {
			log.WithRequestID(ctx).Error(fmt.Sprintf("login set role cache error, userID %d", oauth2User.User.ID), zap.Error(err))
		}
	} else {
		// set a sentinel so other parts know user has no roles
		if err := receiver.cacheStore.SetSet(ctx, store.RoleType, oauth2User.User.ID, []any{constant.EmptyRoleSentinel}, nil); err != nil {
			log.WithRequestID(ctx).Error(fmt.Sprintf("login set empty role cache error,userID %d", oauth2User.User.ID), zap.Error(err))
		}
	}

	return &types.UserLoginResponse{User: oauth2User.User, Token: token}, nil
}

// oauth2GetUser 获取或创建 OAuth2 用户及对应的系统用户
func (receiver *UserService) oauth2GetUser(ctx context.Context, provider string, userInfo any) (*model.Oauth2User, error) {
	var (
		oauth2User *model.Oauth2User
		user       *model.User
		roles      []*model.Role
		oauth2sql  = oauth2.WithContext(ctx)
		uSql       = u.WithContext(ctx)
		userName   string
	)

	email, err := helper.GetOAuth2Field(userInfo, helper.EmailFields...)
	if err != nil {
		return nil, err
	}

	if oauth2User, err = oauth2sql.Where(oauth2.Email.Eq(email)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		userInfoByte, err := json.Marshal(userInfo)
		if err != nil {
			return nil, err
		}
		if err = oauth2sql.Create(model.NewOauth2User(email, provider, userInfoByte)); err != nil {
			return nil, err
		}
	}

	if user, err = uSql.Where(u.Email.Eq(email)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}

		role, err := r.WithContext(ctx).Where(r.Name.Eq("readOnly")).First()
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)

		if userName, err = helper.GetOAuth2Field(userInfo, "name"); err != nil {
			return nil, err
		}
		if userName == "" {
			userName = email
		}
		mobile, _ := helper.GetOAuth2Field(userInfo, "mobile")
		nickName, _ := helper.GetOAuth2Field(userInfo, "nick_name")
		department, _ := helper.GetOAuth2Field(userInfo, "department")
		avatar, _ := helper.GetOAuth2Field(userInfo, "avatar_url")
		user = &model.User{
			Name:       userName,
			NickName:   nickName,
			Email:      email,
			Mobile:     mobile,
			Department: department,
			Avatar:     avatar,
			Status:     helper.Int(model.UserStatusInactive),
			Roles:      roles,
		}
		if err := uSql.Create(user); err != nil {
			return nil, err
		}
	}

	if oauth2User, err = oauth2sql.Where(oauth2.Email.Eq(email)).Preload(oauth2.User.Roles).First(); err != nil {
		return nil, err
	}
	return oauth2User, nil
}

func (receiver *UserService) OAuth2Provider(_ context.Context) ([]string, error) {
	data, err := receiver.localCache.GetCache(constant.OAuth2ProviderList)
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

func (receiver *UserService) OAuth2Activate(ctx context.Context, req *types.OAuthActivateRequest) (*types.UserLoginResponse, error) {
	if req.ID <= 0 {
		return nil, errors.New("id cannot be empty")
	}
	if len(req.Password) < 8 {
		return nil, errors.New("Password greater than or equal to 8")
	}
	if req.Password != req.ConfirmPassword {
		return nil, errors.New("password not match")
	}

	var (
		user *model.User
		err  error
		sql  = u.WithContext(ctx).Where(u.ID.Eq(int64(req.ID)))
	)

	if user, err = sql.First(); err != nil {
		return nil, err
	}

	password, err := receiver.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password error: %v", err)
	}

	user.Password = password
	user.Status = helper.Int(model.UserStatusActive)

	if _, err := sql.Updates(user); err != nil {
		return nil, fmt.Errorf("update user error: %v", err)
	}

	token, err := receiver.jwt.GenerateToken(user.ID, user.Name)
	if err != nil {
		return nil, err
	}
	return types.NewUserLoginResponse(user, token), nil
}
