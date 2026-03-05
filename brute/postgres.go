package brute

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq"
	"github.com/x90skysn3k/brutespray/modules"
)

// pqDialer wraps a ConnectionManager to implement the pq.Dialer
// interface so connections go through SOCKS5/interface binding.
type pqDialer struct {
	cm *modules.ConnectionManager
}

func (d *pqDialer) Dial(network, address string) (net.Conn, error) {
	return d.cm.Dial(network, address)
}

func (d *pqDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	conn, err := d.cm.Dial(network, address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func BrutePostgres(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable", host, port, user, password)

	connector, err := pq.NewConnector(connStr)
	if err != nil {
		return false, false
	}
	connector.Dialer(&pqDialer{cm: cm})

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	db := sql.OpenDB(connector)
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, false // timeout = connection issue
		}
		return false, true
	}
	return true, true
}

func init() { Register("postgres", BrutePostgres) }
