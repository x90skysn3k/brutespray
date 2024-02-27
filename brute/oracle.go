package brute

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	_ "github.com/sijms/go-ora/v2"
)

func BruteOracle(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	service := "ORCL"
	connectionString := fmt.Sprintf("oracle://%s:%s@%s:%d/%s", user, password, host, port, service)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		db  *sql.DB
		err error
	}

	done := make(chan result)
	go func() {
		db, err := sql.Open("oracle", connectionString)
		if err != nil {
			done <- result{nil, err}
			return
		}
		err = db.Ping()
		done <- result{db, err}
	}()

	select {
	case <-timer.C:
		return false, false
	case res := <-done:
		if res.err != nil {
			return false, true
		}
		defer res.db.Close()
		return true, true
	}
}
