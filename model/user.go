package model

import (
	"time"

	"gorm.io/gorm"
)

const (
	ModelNameUser = "User"
	PreloadUsers  = "Users"
)

const (
	UserStatusActive = iota + 1
	UserStatusDisabled
	UserStatusInactive
)

type User struct {
	ID         int64          `gorm:"column:id;primarykey;autoIncrement" json:"id"`
	CreatedAt  time.Time      `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt  time.Time      `gorm:"column:updated_at" json:"updatedAt"`
	DeletedAt  gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
	Name       string         `gorm:"column:name;comment:用户名称;size:50" json:"name"`
	NickName   string         `gorm:"column:nick_name;comment:用户昵称;size:50" json:"nickName"`
	Department string         `gorm:"column:department;comment:用户部门;size:50" json:"department"`
	Email      string         `gorm:"column:email;comment:邮箱;size:100" json:"email"`
	Password   string         `gorm:"column:password;comment:用户密码;size:255" json:"-"`
	Avatar     string         `gorm:"column:avatar;comment:用户头像;size:1024" json:"avatar"`
	Mobile     string         `gorm:"column:mobile;comment:用户手机号;size:20" json:"mobile"`
	Status     *int           `gorm:"column:status;comment:用户状态,1可用,2禁用,3未激活;size:1;default:1" json:"status"`
	Roles      []*Role        `gorm:"many2many:user_roles" json:"roles,omitempty"`
}

func (receiver *User) TableName() string {
	return "users"
}

// UserOption 定义为一个接受 *User 指针并对其进行修改的函数
type UserOption func(*User)

// NewUser 创建用户实例，接收可变长的 Option 参数
func NewUser(opts ...UserOption) *User {
	defaultStatus := UserStatusActive

	u := &User{
		Status: &defaultStatus,
		Roles:  make([]*Role, 0),
	}

	for _, opt := range opts {
		opt(u)
	}

	return u
}

// WithName 设置用户名称
func WithName(name string) UserOption {
	return func(u *User) {
		u.Name = name
	}
}

// WithNickName 设置昵称
func WithNickName(nickName string) UserOption {
	return func(u *User) {
		u.NickName = nickName
	}
}

// WithEmail 设置邮箱
func WithEmail(email string) UserOption {
	return func(u *User) {
		u.Email = email
	}
}

// WithPassword 设置密码
// 注意：实际业务中这里可能需要传入加密后的 hash，或者在内部进行加密
func WithPassword(password string) UserOption {
	return func(u *User) {
		u.Password = password
	}
}

// WithMobile 设置手机号
func WithMobile(mobile string) UserOption {
	return func(u *User) {
		u.Mobile = mobile
	}
}

// WithDepartment 设置部门
func WithDepartment(dept string) UserOption {
	return func(u *User) {
		u.Department = dept
	}
}

// WithAvatar 设置头像
func WithAvatar(avatar string) UserOption {
	return func(u *User) {
		u.Avatar = avatar
	}
}

// WithStatus 设置状态
// 注意：User 结构体中 Status 是 *int，这里处理指针转换
func WithStatus(status int) UserOption {
	return func(u *User) {
		u.Status = &status
	}
}

// WithRoles 设置角色
func WithRoles(roles []*Role) UserOption {
	return func(u *User) {
		u.Roles = roles
	}
}
