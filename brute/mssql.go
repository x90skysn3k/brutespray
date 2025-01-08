package brute

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/x90skysn3k/brutespray/modules"
)

func BruteMSSQL(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	connString := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s", host, port, user, password)

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		return false, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false, false
	}
	_ = conn.Close()

	db, err := sql.Open("mssql", connString)
	if err != nil {
		//fmt.Println(err)
		return false, true
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		//fmt.Println(err)
		return false, true
	}

	return true, true
}
