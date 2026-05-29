package brute

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

func BruteCassandra(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		cluster := gocql.NewCluster(fmt.Sprintf("%s:%d", host, port))
		cluster.ProtoVersion = 4
		cluster.ConnectTimeout = timeout
		cluster.Timeout = timeout
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: user,
			Password: password,
		}
		cluster.DisableInitialHostLookup = true
		sess, err := cluster.CreateSession()
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "Authentication") ||
				strings.Contains(msg, "Bad credentials") ||
				strings.Contains(msg, "Unauthorized") {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer sess.Close()
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("cassandra", BruteCassandra) }
