package brute

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/x90skysn3k/brutespray/modules" // Assuming this package is available
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
	"github.com/x90skysn3k/grdp/protocol/pdu"
	"github.com/x90skysn3k/grdp/protocol/sec"
	"github.com/x90skysn3k/grdp/protocol/t125"
	"github.com/x90skysn3k/grdp/protocol/tpkt"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

func BruteRDP(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager, domain string) (bool, bool) {
	glog.SetLevel(pdu.STREAM_LOW)
	logger := log.New(io.Discard, "", 0)
	glog.SetLogger(logger)

	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		glog.Errorf("[dial err] %v", err)
		return false, false
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	tpkt := tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, password))
	x224 := x224.New(tpkt)
	mcs := t125.NewMCSClient(x224)
	sec := sec.NewClient(mcs)
	pdu := pdu.NewClient(sec)

	sec.SetUser(user)
	sec.SetPwd(password)

	tpkt.SetFastPathListener(sec)
	sec.SetFastPathListener(pdu)
	pdu.SetFastPathSender(tpkt)

	success := make(chan bool, 1)

	go func() {
		err := x224.Connect()
		if err != nil {
			glog.Errorf("[x224 connect err] %v", err)
			success <- false
		}
	}()

	pdu.On("error", func(e error) {
		glog.Error("error", e)
		success <- false
	})
	pdu.On("close", func() {
		glog.Info("on close")
		success <- false
	})
	pdu.On("ready", func() {
		glog.Info("on ready")
		success <- true
	})
	pdu.On("success", func() {
		glog.Info("on success")
		success <- true
	})

	// Wait for a result with a timeout to prevent blocking forever (3.2 fix)
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-success:
		return result, true
	case <-timer.C:
		// Force the connection closed so the blocked goroutine exits
		_ = conn.SetDeadline(time.Now())
		select {
		case result := <-success:
			return result, true
		default:
			return false, false
		}
	}
}
