package brute

import (
	"math"
	"sync"
	"time"

	"github.com/x90skysn3k/brutespray/modules"
)

type retryInfo struct {
	key           string
	retries       int
	maxRetries    int
	skip          bool
	skipped       bool
	retrying      bool
	retryMapMutex *sync.Mutex
}

func ClearMaps() {
	retryInfoMap = make(map[string]*retryInfo)
}

var retryInfoMap = make(map[string]*retryInfo)

func getRetryInfo(h modules.Host, maxRetries int) *retryInfo {
	key := h.Host + ":" + h.Service

	retryInfoMap[key].retryMapMutex.Lock()
	defer retryInfoMap[key].retryMapMutex.Unlock()

	if retryInfoMap[key] == nil {
		retryInfoMap[key] = &retryInfo{
			key:           key,
			retries:       0,
			maxRetries:    maxRetries,
			skip:          false,
			skipped:       false,
			retrying:      false,
			retryMapMutex: &sync.Mutex{},
		}
	}
	return retryInfoMap[key]
}

func RunBrute(h modules.Host, u string, p string, progressCh chan<- int, timeout time.Duration, maxRetries int, output string, socks5 string, netInterface string) bool {
	service := h.Service
	retryInfo := getRetryInfo(h, maxRetries)
	var result bool
	var con_result bool
	var delayTime time.Duration = 1 * time.Second

	for {
		retryInfo.retryMapMutex.Lock()
		retries := retryInfo.retries
		if retries >= maxRetries && !retryInfo.skip {
			retryInfo.skip = true
			modules.PrintSkipping(h.Host, service, retries, maxRetries)
			retryInfo.skipped = true
			retryInfo.retryMapMutex.Unlock()
			return false
		}
		retries++
		retryInfo.retries = retries
		retryInfo.retryMapMutex.Unlock()

		if retryInfo.skipped {
			return false
		}

		switch service {
		// Bruteforce functions go here
		default:
			return con_result
		}
		if con_result {
			break
		} else {
			delayTime = time.Duration(int64(time.Second) * int64(math.Min(float64(retries), float64(delayTime))))
			retryInfo.retrying = true
			modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retryInfo.retrying, output, delayTime)
			time.Sleep(delayTime)
		}
	}
	modules.PrintResult(service, h.Host, h.Port, u, p, result, con_result, progressCh, retryInfo.retrying, output, delayTime)
	return con_result
}
