package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/x90skysn3k/brutespray/modules"
)

func init() {
	// Register a no-op dialer at init. The actual CM-backed dialer is
	// registered per-attempt because the ConnectionManager is not available
	// at init time. The init registration ensures the driver knows the
	// network name.
	mysql.RegisterDialContext("brutespray", func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("brutespray dialer not configured")
	})
}

func BruteMYSQL(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Register a CM-backed dialer so the MySQL driver uses SOCKS5/interface
	// binding and doesn't create a second connection (1.4 fix).
	mysql.RegisterDialContext("brutespray", func(ctx context.Context, _ string) (net.Conn, error) {
		conn, err := cm.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		return conn, nil
	})

	connString := fmt.Sprintf("%s:%s@brutespray(%s)/?timeout=%s", user, password, addr, timeout.String())

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db, err := sql.Open("mysql", connString)
	if err != nil {
		return false, false
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		// Distinguish connection errors from auth errors. MySQL auth errors
		// contain "Access denied".
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			_ = mysqlErr
			return false, true // auth-level error
		}
		// Check if it's likely a connection failure vs auth failure
		if ctx.Err() != nil {
			return false, false // timeout/cancel = connection issue
		}
		return false, true
	}
	return true, true
}
