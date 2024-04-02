package brute

import (
	"fmt"
	"net"
	"sync"
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
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		glog.Errorf("[dial err] %v", err)
		return false, false // Connection failed
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

	var wg sync.WaitGroup
	wg.Add(1)

	err = x224.Connect()
	if err != nil {
		glog.Errorf("[x224 connect err] %v", err)
		return false, false
	}

	pdu.On("error", func(e error) {
		glog.Error("error", e)
		wg.Done()
	})
	pdu.On("close", func() {
		glog.Info("on close")
		wg.Done()
	})
	pdu.On("success", func() {
		glog.Info("on success")
		wg.Done()
	})
	pdu.On("ready", func() {
		glog.Info("on ready")
		wg.Done()
	})

	wg.Wait()
	return true, true // Return authentication status
}
