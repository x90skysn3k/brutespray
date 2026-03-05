package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"github.com/x90skysn3k/brutespray/modules"
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

func BruteOracle(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	connString := fmt.Sprintf("oracle://%s:%s@%s:%d/", user, password, host, port)

	connector := go_ora.NewConnector(connString)
	oraConn, ok := connector.(*go_ora.OracleConnector)
	if !ok {
		return false, false
	}
	oraConn.Dialer(&oracleDialer{cm: cm})

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db := sql.OpenDB(connector)
	defer db.Close()

	err := db.PingContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, false // timeout = connection issue
		}
		return false, true
	}
	return true, true
}

func init() { Register("oracle", BruteOracle) }
