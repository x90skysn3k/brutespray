package brutespray

import "github.com/x90skysn3k/brutespray/v2/modules"

type resumeCursor struct {
	remaining int
}

func newResumeCursor(cp *modules.Checkpoint, host modules.Host) resumeCursor {
	if cp == nil {
		return resumeCursor{}
	}
	return resumeCursor{remaining: cp.GetAttemptedCount(host.Host, host.Port, host.Service)}
}

func (c *resumeCursor) skipNext() bool {
	if c == nil || c.remaining <= 0 {
		return false
	}
	c.remaining--
	return true
}
