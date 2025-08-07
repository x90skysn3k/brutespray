package brute

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
	"github.com/x90skysn3k/grdp/protocol/pdu"
	"github.com/x90skysn3k/grdp/protocol/sec"
	"github.com/x90skysn3k/grdp/protocol/t125"
	"github.com/x90skysn3k/grdp/protocol/tpkt"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

// SafeBruteRDP provides a safer alternative to BruteRDP with better error handling
func SafeBruteRDP(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	// Validate input parameters
	if host == "" || port <= 0 || port > 65535 {
		glog.Errorf("[rdp validation] Invalid host or port: %s:%d", host, port)
		return false, false
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	} else if timeout > 30*time.Second {
		timeout = 30 * time.Second // Cap maximum timeout
	}

	// Set up logging
	glog.SetLevel(pdu.STREAM_LOW)
	logger := log.New(io.Discard, "", 0)
	glog.SetLogger(logger)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Global panic recovery
	defer func() {
		if r := recover(); r != nil {
			glog.Errorf("[rdp safe panic recovered] %v", r)
		}
	}()

	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		glog.Errorf("[connection manager error] %v", err)
		return false, false
	}

	// Use context for dialing
	conn, err := cm.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		glog.Errorf("[dial err] %v", err)
		return false, false
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// Set connection deadlines
	deadline := time.Now().Add(timeout)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(deadline)
	}

	// Pre-validate connection before proceeding
	if !isConnectionHealthy(conn) {
		glog.Errorf("[rdp connection] Connection is not healthy")
		return false, false
	}

	return performRDPHandshake(ctx, conn, user, password, timeout)
}

// isConnectionHealthy performs basic connection validation
func isConnectionHealthy(conn net.Conn) bool {
	// Set a short deadline for this test
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // Reset deadline

	// Try to read any immediately available data
	buffer := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := conn.Read(buffer)

	// Reset the deadline
	conn.SetReadDeadline(time.Time{})

	// If we get a timeout, that's actually good - it means the connection is open
	// If we get other errors, the connection might be problematic
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true // Timeout is expected and good
		}
		// Other errors might indicate problems
		return false
	}

	return true
}

// performRDPHandshake handles the actual RDP handshake with enhanced error handling
func performRDPHandshake(ctx context.Context, conn net.Conn, user, password string, timeout time.Duration) (bool, bool) {
	defer func() {
		if r := recover(); r != nil {
			glog.Errorf("[rdp handshake panic recovered] %v", r)
		}
	}()

	// Create RDP protocol stack with error checking
	socketLayer := core.NewSocketLayer(conn)
	if socketLayer == nil {
		glog.Errorf("[rdp] Failed to create socket layer")
		return false, false
	}

	nlaLayer := nla.NewNTLMv2("", user, password)
	if nlaLayer == nil {
		glog.Errorf("[rdp] Failed to create NLA layer")
		return false, false
	}

	tpktLayer := tpkt.New(socketLayer, nlaLayer)
	if tpktLayer == nil {
		glog.Errorf("[rdp] Failed to create TPKT layer")
		return false, false
	}

	x224Layer := x224.New(tpktLayer)
	if x224Layer == nil {
		glog.Errorf("[rdp] Failed to create X224 layer")
		return false, false
	}

	mcsLayer := t125.NewMCSClient(x224Layer)
	if mcsLayer == nil {
		glog.Errorf("[rdp] Failed to create MCS layer")
		return false, false
	}

	secLayer := sec.NewClient(mcsLayer)
	if secLayer == nil {
		glog.Errorf("[rdp] Failed to create Security layer")
		return false, false
	}

	pduLayer := pdu.NewClient(secLayer)
	if pduLayer == nil {
		glog.Errorf("[rdp] Failed to create PDU layer")
		return false, false
	}

	// Configure layers
	secLayer.SetUser(user)
	secLayer.SetPwd(password)

	tpktLayer.SetFastPathListener(secLayer)
	secLayer.SetFastPathListener(pduLayer)
	pduLayer.SetFastPathSender(tpktLayer)

	// Create channels for communication
	result := make(chan bool, 1)
	errorChan := make(chan error, 1)

	// Set up event handlers with better error management
	pduLayer.On("error", func(e error) {
		glog.Errorf("[rdp pdu error] %v", e)
		select {
		case errorChan <- e:
		default:
		}
	})

	pduLayer.On("close", func() {
		glog.Info("[rdp] Connection closed")
		select {
		case result <- false:
		default:
		}
	})

	pduLayer.On("ready", func() {
		glog.Info("[rdp] Connection ready")
		select {
		case result <- true:
		default:
		}
	})

	pduLayer.On("success", func() {
		glog.Info("[rdp] Authentication successful")
		select {
		case result <- true:
		default:
		}
	})

	// Start connection in goroutine with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				glog.Errorf("[rdp connect goroutine panic recovered] %v", r)
				select {
				case errorChan <- fmt.Errorf("panic in connect: %v", r):
				default:
				}
			}
		}()

		err := x224Layer.Connect()
		if err != nil {
			glog.Errorf("[rdp x224 connect error] %v", err)
			select {
			case errorChan <- err:
			default:
			}
		}
	}()

	// Wait for result with timeout
	select {
	case success := <-result:
		return success, true
	case err := <-errorChan:
		glog.Errorf("[rdp handshake error] %v", err)
		return false, true
	case <-ctx.Done():
		glog.Errorf("[rdp] Context timeout or cancellation")
		return false, false
	case <-time.After(timeout + 2*time.Second):
		glog.Errorf("[rdp] Operation timeout after %v", timeout)
		return false, false
	}
}
