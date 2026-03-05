package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/x90skysn3k/brutespray/modules"
)

var mysqlDialerID int64

func BruteMYSQL(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) *BruteResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Use a unique dialer name per invocation to avoid a data race when
	// multiple goroutines brute-force different MySQL hosts concurrently.
	dialerName := fmt.Sprintf("brutespray_%d", atomic.AddInt64(&mysqlDialerID, 1))

	mysql.RegisterDialContext(dialerName, func(ctx context.Context, _ string) (net.Conn, error) {
		conn, err := cm.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		return conn, nil
	})

	connString := fmt.Sprintf("%s:%s@%s(%s)/?timeout=%s", user, password, dialerName, addr, timeout.String())

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db, err := sql.Open("mysql", connString)
	if err != nil {
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			_ = mysqlErr
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err} // auth-level error
		}
		if ctx.Err() != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err} // timeout/cancel = connection issue
		}
		return &BruteResult{AuthSuccess: false, ConnectionSuccess: true, Error: err}
	}
	return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
}

func init() { Register("mysql", BruteMYSQL) }
