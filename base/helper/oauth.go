package helper

import (
	"errors"
	"fmt"
)

var EmailFields = []string{"email", "enterprise_email"}

// GetOAuth2Field 获取 OAuth2 登录用户的 email
func GetOAuth2Field(userInfo any, fields ...string) (string, error) {
	userInfoMap, ok := userInfo.(map[string]any)
	if !ok {
		return "", errors.New("oauth2 user information verification failed: not a map")
	}

	for _, field := range fields {
		v, exists := userInfoMap[field]
		if !exists {
			continue
		}

		if fieldStr, ok := v.(string); ok {
			if fieldStr != "" {
				return fieldStr, nil
			}
		}
	}

	return "", fmt.Errorf("%v not found in user info", fields)
}
