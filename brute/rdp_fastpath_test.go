package brute

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

// Throwaway smoke: drives BruteRDP against a mock server that answers the
// X.224 Connection Request with NEG_RSP (HYBRID) and then immediately pushes
// a FastPath output frame — the brutespray#363 trigger. Pre-fix grdp
// SIGSEGVs the whole test binary (nil fastPathListener); post-fix BruteRDP
// must return a normal result instead of crashing the process.
func TestRDPFastPathAfterNegotiation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// read X.224 Connection Request (TPKT header then body)
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			t.Log("read req hdr:", err)
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(hdr[2:4]))-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Log("read req body:", err)
			return
		}

		// NEG_RSP advertising HYBRID: TPKT + X.224 data (DT=0xD0, EoT) +
		// RDP_NEG_RSP (type 2, flags 0, len 8, selectedProto HYBRID=0x02)
		x224 := []byte{3, 0x80, 2, 0x00, 1, 0x08, 0, 0, 0, 2}
		tpkt := make([]byte, 0, 4+len(x224))
		tpkt = append(tpkt, 3, 0)
		tpkt = binary.BigEndian.AppendUint16(tpkt, uint16(4+len(x224)))
		tpkt = append(tpkt, x224...)
		if _, err := conn.Write(tpkt); err != nil {
			t.Log("write neg rsp:", err)
			return
		}

		// FastPath output frame: first byte 0x00 (short header, length 5),
		// 2 payload bytes. Not an X.224 TPDU -> routes to recvFastPath.
		if _, err := conn.Write([]byte{0x00, 0x05, 0xAA, 0xBB, 0xCC}); err != nil {
			t.Log("write fastpath:", err)
			return
		}
		time.Sleep(2 * time.Second) // let the client read it
	}()

	cm, err := modules.NewConnectionManager("", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	res := BruteRDP("127.0.0.1", port, "user", "pass", 4*time.Second, cm, ModuleParams{})
	if res == nil {
		t.Fatal("nil result")
	}
	t.Logf("survived FastPath push: auth=%v conn=%v err=%v", res.AuthSuccess, res.ConnectionSuccess, res.Error)
}
