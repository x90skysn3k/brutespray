package brute

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/sijms/go-ora/v2"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteOracle(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {

	connectionString := fmt.Sprintf("%s:%s@%s:%d", user, password, host, port)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		_ = err
		//fmt.Println("Connection Error:", err)
		return false, false
	}
	defer conn.Close()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		db  *sql.DB
		err error
	}

	done := make(chan result, 1)
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
			_ = res.err
			//fmt.Println("Database Ping Error:", res.err)
			return false, true
		}
		defer res.db.Close()
		return true, true
	}
}
