package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"
)

func BruteMSSQL(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	connString := fmt.Sprintf("server=%s:%d;user id=%s;password=%s;database=master", host, port, user, password)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	_ = conn.Close()

	db, err := sql.Open("mssql", connString)
	if err != nil {
		return false, true
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		return false, true
	}
	return true, true
}
