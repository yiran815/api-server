package constant

import (
	"errors"
)

var (
	ErrAuthFailed    = errors.New("auth failed")
	ErrNoPermission  = errors.New("access forbidden")
	ErrLoginFailed   = errors.New("incorrect username or password")
	ErrUserNotFound  = errors.New("user not found")
	ErrPasswordWrong = errors.New("password incorrect")
)
