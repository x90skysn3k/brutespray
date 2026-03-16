package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"github.com/x90skysn3k/brutespray/v2/modules"
)

// oracleDialer wraps a ConnectionManager to implement the go-ora
// DialerContext interface so connections go through SOCKS5/interface binding.
type oracleDialer struct {
	cm *modules.ConnectionManager
}

func (d *oracleDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.cm.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func BruteOracle(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	connString := fmt.Sprintf("oracle://%s:%s@%s:%d/", url.QueryEscape(user), url.QueryEscape(password), host, port)

	connector := go_ora.NewConnector(connString)
	oraConn, ok := connector.(*go_ora.OracleConnector)
	if !ok {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: nil}
	}
	oraConn.Dialer(&oracleDialer{cm: cm})

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db := sql.OpenDB(connector)
	defer db.Close()

	err := db.PingContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err} // timeout = connection issue
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}
	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func init() { Register("oracle", BruteOracle) }
