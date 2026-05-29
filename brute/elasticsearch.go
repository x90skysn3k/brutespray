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

func BruteElasticsearch(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, params ModuleParams) *BruteResult {
	return RunWithTimeout(timeout, func(ctx context.Context) *BruteResult {
		scheme := "http"
		if params["tls"] == "true" {
			scheme = "https"
		}
		endpoint := fmt.Sprintf("%s://%s/_cluster/health", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
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
		req.SetBasicAuth(user, password)
		resp, err := cl.Do(req)
		if err != nil {
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: false, Error: err}
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			return &BruteResult{AuthSuccess: true, ConnectionSuccess: true}
		case 401, 403:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("elasticsearch %d", resp.StatusCode)}
		default:
			return &BruteResult{AuthSuccess: false, ConnectionSuccess: true,
				Error: fmt.Errorf("elasticsearch status %d", resp.StatusCode)}
		}
	})
}

func init() { Register("elasticsearch", BruteElasticsearch) }
