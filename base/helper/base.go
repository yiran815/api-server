package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/yiran15/api-server/base/constant"
	"github.com/yiran15/api-server/model"
)

func InArray[T comparable](arr []T, val T) bool {
	return slices.Contains(arr, val)
}

func String(in string) *string {
	return &in
}

func Int(in int) *int {
	return &in
}

func ToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("to map marshal failed: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("to map unmarshal failed: %w", err)
	}
	return m, nil
}

// RemoveDuplicates 是一个泛型去重函数，接受类型为 T 的切片，其中 T 需满足 comparable 约束。
// 返回去重后的切片，保持原顺序。
func RemoveDuplicates[T comparable](slice []T) []T {
	if len(slice) == 0 {
		return slice
	}
	// 使用 map 记录已出现的元素
	seen := make(map[T]struct{})
	// 结果切片，保持原顺序
	result := make([]T, 0, len(slice))

	for _, item := range slice {
		// 如果元素未出现过，添加到结果并标记为已出现
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// GetRequestIDFromContext 从上下文中获取请求 ID
func GetRequestIDFromContext(ctx context.Context) string {
	if reqID, ok := ctx.Value(constant.RequestIDContextKey).(string); ok {
		return reqID
	}
	return ""
}

// ValidateRoleIds 校验请求的角色 ID 列表是否都存在于数据库中的角色列表中
func ValidateRoleIds(reqRoleIds []int64, roles []*model.Role) error {
	if len(reqRoleIds) == 0 {
		return errors.New("role ids is empty")
	}

	// 构建 DB role ID 集合
	roleSet := make(map[int64]struct{}, len(roles))
	for _, role := range roles {
		roleSet[role.ID] = struct{}{}
	}

	// 校验请求的 roleId 是否都存在
	notFound := make([]int64, 0)
	for _, id := range reqRoleIds {
		if _, ok := roleSet[id]; !ok {
			notFound = append(notFound, id)
		}
	}

	if len(notFound) > 0 {
		return fmt.Errorf("roles not found: %v", notFound)
	}
	return nil
}

// ValidateRoleApis 校验请求的角色 API ID 列表是否都存在于数据库中的 API 列表中
func ValidateRoleApis(reqApis []int64, apis []*model.Api) error {
	if len(reqApis) == 0 {
		return errors.New("api ids is empty")
	}

	if len(apis) == 0 {
		return fmt.Errorf("apis not found: %v", reqApis)
	}

	// 构建已存在 API 的集合
	apiSet := make(map[int64]struct{}, len(apis))
	for _, api := range apis {
		apiSet[api.ID] = struct{}{}
	}

	// 校验请求的 API 是否全部存在
	notFound := make([]int64, 0)
	for _, id := range reqApis {
		if _, ok := apiSet[id]; !ok {
			notFound = append(notFound, id)
		}
	}

	if len(notFound) > 0 {
		return fmt.Errorf("apis not found: %v", notFound)
	}
	return nil
}
