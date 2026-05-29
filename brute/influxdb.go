package brute

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// BruteInfluxDB targets InfluxDB. v2 (default): `password` is the InfluxDB
// token; the endpoint /api/v2/orgs returns 200 on valid auth, 401 on invalid.
// v1: pass `-m mode:v1` to use /ping with HTTP basic auth instead.
func BruteInfluxDB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		scheme := "http"
		if params["tls"] == "true" {
			scheme = "https"
		}
		v1 := params["mode"] == "v1"
		var endpoint string
		if v1 {
			endpoint = fmt.Sprintf("%s://%s/ping", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
		} else {
			endpoint = fmt.Sprintf("%s://%s/api/v2/orgs", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
		}
		tr := &http.Transport{
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return cm.Dial(network, addr)
			},
			DisableKeepAlives: true,
		}
		cl := &http.Client{Transport: tr, Timeout: timeout}
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		if v1 {
			req.SetBasicAuth(user, password)
		} else {
			req.Header.Set("Authorization", "Token "+password)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case 200, 204:
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		case 401, 403:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("influxdb %d", resp.StatusCode)}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("influxdb status %d", resp.StatusCode)}
		}
	})
}

func init() { Register("influxdb", BruteInfluxDB) }
