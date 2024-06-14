package brute

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
	"github.com/x90skysn3k/grdp/protocol/pdu"
	"github.com/x90skysn3k/grdp/protocol/sec"
	"github.com/x90skysn3k/grdp/protocol/t125"
	"github.com/x90skysn3k/grdp/protocol/tpkt"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

func BruteRDP(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	glog.SetLevel(pdu.STREAM_LOW)
	logger := log.New(io.Discard, "", 0)
	glog.SetLogger(logger)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		glog.Errorf("[dial err] %v", err)
		return false, false
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	tpkt := tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2("", user, password))
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

	result := <-success
	return result, true
}
