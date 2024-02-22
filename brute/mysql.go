package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func BruteMYSQL(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	connString := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=5s", user, password, host, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db, err := sql.Open("mysql", connString)
	if err != nil {
		return false, false
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		return false, true
	}
	return true, true
}
