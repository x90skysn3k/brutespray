package brute

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteRedis(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Username: user, // Redis 6.0+ ACL
		Password: password,
		DB:       0,
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
			return false, true
		}
		// If it's not an explicit auth error, assume connection failure
		// (timeout, connection refused, etc.)
		return false, false
	}

	return true, true
}
