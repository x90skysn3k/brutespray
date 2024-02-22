package brute

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	_ "github.com/lib/pq"
)

func BrutePostgres(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}

	defer conn.Close()

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable", host, port, user, password)
	db, _ := sql.Open("postgres", connStr)
	err = db.Ping()
	if err != nil {
		if err.Error() == "pq: password authentication failed for user" {
			return false, true
		} else {
			return false, true
		}
	}
	defer db.Close()

	return true, true
}
