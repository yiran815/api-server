package helper

import (
	"errors"
)

var emailFields = []string{"email", "enterprise_email"}

// GetOAuth2Email 获取 OAuth2 登录用户的 email
func GetOAuth2Email(userInfo any) (string, error) {
	userInfoMap, ok := userInfo.(map[string]any)
	if !ok {
		return "", errors.New("oauth2 user information verification failed: not a map")
	}

	for _, field := range emailFields {
		v, exists := userInfoMap[field]
		if !exists {
			continue
		}

		if emailStr, ok := v.(string); ok {
			if emailStr != "" {
				return emailStr, nil
			}
		}
	}

	return "", errors.New("email not found in user info")
}
