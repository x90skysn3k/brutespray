package brute

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteNeo4j attempts to authenticate against a Neo4j Bolt v5 server.
//
// Note: neo4j-go-driver/v5 does not expose a custom net.Dialer on the public
// Config API, so proxy/interface routing via cm does not apply to Neo4j
// attempts. The cm parameter is accepted for interface consistency but unused.
func BruteNeo4j(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		uri := fmt.Sprintf("bolt://%s:%d", host, port)
		driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""),
			func(c *neo4j.Config) {
				c.SocketConnectTimeout = timeout
			})
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer driver.Close(ctx)

		err = driver.VerifyConnectivity(ctx)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "AuthenticationRateLimit") ||
				strings.Contains(msg, "Unauthorized") ||
				strings.Contains(msg, "credentials") ||
				strings.Contains(msg, "Neo.ClientError.Security.Unauthorized") {
				return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
			}
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
	})
}

func init() { Register("neo4j", BruteNeo4j) }
