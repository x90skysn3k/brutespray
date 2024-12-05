package brute

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/x90skysn3k/brutespray/modules"

	_ "github.com/go-sql-driver/mysql"
)

func BruteMYSQL(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	cm, err := modules.NewConnectionManager(socks5, timeout)
	if err != nil {
		return false, false
	}

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
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
