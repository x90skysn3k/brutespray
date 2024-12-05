package brute

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/x90skysn3k/brutespray/modules"
)

func BrutePostgres(host string, port int, user, password string, timeout time.Duration, socks5 string) (bool, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		client *sql.DB
		err    error
	}
	done := make(chan result)

	cm, err := modules.NewConnectionManager(socks5, timeout)
	if err != nil {
		return false, false
	}

	go func() {
		conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer conn.Close()

		connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable", host, port, user, password)

		db, err := sql.Open("postgres", connStr)
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer db.Close()

		err = db.Ping()
		done <- result{db, err}
	}()

	select {
	case <-timer.C:
		return false, false
	case result := <-done:
		if result.client != nil {
			_ = result.client
		}
		if result.err != nil {
			if result.err.Error() == "pq: password authentication failed for user" {
				return false, true
			} else {
				return false, true
			}
		}
		return true, true
	}
}
