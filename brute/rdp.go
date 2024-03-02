package brute

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

func BruteRDP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	domain := ".\\"
	width := 600
	height := 600

	target := fmt.Sprintf("%s:%d", host, port)

	glog.SetLevel(glog.INFO)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)

	client := NewRdpClient(target, width, height, glog.INFO)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		success bool
		err     error
	}
	done := make(chan result)

	go func() {
		err := client.Login()
		success := err == nil
		done <- result{success, err}
		client.Close()
	}()

	select {
	case <-ctx.Done():
		return false, false
	case res := <-done:
		if res.err != nil {
			return false, true
		}
		return true, true
	}
}

type RdpClient struct {
	Host   string // ip:port
	Width  int
	Height int
	tpkt   *tpkt.TPKT
	x224   *x224.X224
	mcs    *t125.MCSClient
	sec    *sec.Client
	pdu    *pdu.Client
}

func NewRdpClient(host string, width, height int, logLevel glog.LEVEL) *RdpClient {
	return &RdpClient{
		Host:   host,
		Width:  width,
		Height: height,
	}
}

func (g *RdpClient) Login() error {
	conn, err := net.DialTimeout("tcp", g.Host, 3*time.Second)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, password))
	g.x224 = x224.New(g.tpkt)

	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.mcs.SetClientDesktop(uint16(g.Width), uint16(g.Height))
	g.sec.SetUser(g.user)
	g.sec.SetPwd(g.password)
	g.sec.SetDomain(g.domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.sec.SetChannelSender(g.mcs)

	g.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	return nil
}

func (g *RdpClient) Close() {
	if g != nil && g.tpkt != nil {
		g.tpkt.Close()
	}
}
