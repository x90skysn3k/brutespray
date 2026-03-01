package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	mssql "github.com/denisenkom/go-mssqldb"
	"github.com/x90skysn3k/brutespray/modules"
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

func BruteMSSQL(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	connString := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s", host, port, user, password)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	connector, err := mssql.NewConnector(connString)
	if err != nil {
		return false, false
	}
	connector.Dialer = &mssqlDialer{cm: cm}

	db := sql.OpenDB(connector)
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, false // timeout = likely connection issue
		}
		return false, true
	}

	return true, true
}
