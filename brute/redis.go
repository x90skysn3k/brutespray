package brute

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteRedis(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db := 0
	if dbStr := params["db"]; dbStr != "" {
		if v, err := strconv.Atoi(dbStr); err == nil && v >= 0 {
			db = v
		}
	}

	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Username: user, // Redis 6.0+ ACL
		Password: password,
		DB:       db,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cm.Dial(network, addr)
		},
	}

	rdb := redis.NewClient(opts)
	defer rdb.Close()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		msg := err.Error()
		// Check for authentication failure messages
		if strings.Contains(msg, "WRONGPASS") ||
			strings.Contains(msg, "NOAUTH") ||
			strings.Contains(msg, "ERR invalid password") ||
			strings.Contains(msg, "invalid username-password pair") {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
		}
		// If it's not an explicit auth error, assume connection failure
		// (timeout, connection refused, etc.)
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}

	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func init() { Register("redis", BruteRedis) }
