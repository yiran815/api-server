package http_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"resty.dev/v3"
)

func TestCurl(t *testing.T) {
	client := resty.New()
	defer client.Close()
	loc, _ := time.LoadLocation("Asia/Shanghai")
	tt, _ := time.ParseInLocation("2006-01-02 15:04:05", "2025-12-02 13:43:10", loc)
	nt := strconv.FormatInt(tt.Unix(), 10)
	fmt.Printf("nt: %s\n", nt)

	res, err := client.R().
		SetQueryParams(map[string]string{
			"query": `sum by (container) (max_over_time(DCGM_FI_DEV_GPU_UTIL{namespace="a1-prod", container="qwen-image"}[1m])) / 100`,
			// "query": `sum (DCGM_FI_DEV_GPU_UTIL{namespace="a1-prod", container="qwen-image"}) by (container) / 100`,
			"time": nt,
		}).
		Get("http://10.99.1.12:30737/api/v1/query")
	if err != nil {
		t.Fatalf("查询失败: %s\n", err)
	}
	fmt.Printf("res: %+v\n", res)
}
