package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// mssqlDialer wraps a ConnectionManager to implement the go-mssqldb Dialer
// interface so connections go through SOCKS5/interface binding (1.4 fix).
type mssqlDialer struct {
	cm *modules.ConnectionManager
}

func (d *mssqlDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.cm.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func BruteMSSQL(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	// Wrap values in braces to escape semicolons per MSSQL connection string spec
	escMssql := func(s string) string {
		if strings.ContainsAny(s, ";{}") {
			return "{" + strings.ReplaceAll(s, "}", "}}") + "}"
		}
		return s
	}
	connString := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s", host, port, escMssql(user), escMssql(password))
	if domain := params["domain"]; domain != "" {
		connString += ";domain=" + escMssql(domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	connector, err := mssql.NewConnector(connString)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	connector.Dialer = &mssqlDialer{cm: cm}

	db := sql.OpenDB(connector)
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err} // timeout = likely connection issue
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}

	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func init() { Register("mssql", BruteMSSQL) }
