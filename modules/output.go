package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pterm/pterm"
)

func getResultString(result bool) string {
	if result {
		return "succeeded"
	} else {
		return "failed"
	}
}

func getConResultString(con_result bool, retrying bool, delayTime time.Duration) string {
	var delaying bool
	if delayTime > 2 {
		delaying = true
	}
	if !retrying {
		return "connection failed, giving up..."
	} else if retrying && delaying {
		return fmt.Sprintf("connection failed, retrying... delayed %s", delayTime)
	} else {
		return "connection failed, retrying..."
	}
}

func WriteToFile(service string, content string, port int, output string) error {
	var dir string
	if output != "brutespray-output" {
		dir = output
	} else {
		dir = output
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.Mkdir(dir, 0755)
		if err != nil {
			return err
		}
	}

	filename := filepath.Join(dir, fmt.Sprintf("%d-%s-success.txt", port, service))
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}

func PrintResult(service string, host string, port int, user string, pass string, result bool, con_result bool, progressCh chan<- int, retrying bool, output string, delayTime time.Duration) {

	if result && con_result {
		if service == "vnc" {
			PrintlnColored(pterm.BgGreen, "Attempt", service, "SUCCESS on host", host, "port", port, "with password", pass, getResultString(result))
			content := fmt.Sprintf("Attempt %s SUCCESS on host %s port %d with password %s %s\n", service, host, port, pass, getResultString(result))
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		} else {
			PrintlnColored(pterm.BgGreen, "Attempt", service, "SUCCESS on host", host, "port", port, "with username", user, "and password", pass, getResultString(result))
			content := fmt.Sprintf("Attempt %s SUCCESS on host %s port %d with username %s and password %s %s\n", service, host, port, user, pass, getResultString(result))
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		}
	} else if !result && con_result {
		if service == "vnc" {
			PrintlnColored(pterm.FgLightRed, "Attempt", service, "on host", host, "port", port, "with password", pass, getResultString(result))
		} else {
			PrintlnColored(pterm.FgLightRed, "Attempt", service, "on host", host, "port", port, "with username", user, "and password", pass, getResultString(result))
		}
	} else if !result && !con_result {
		if service == "vnc" {
			PrintlnColored(pterm.FgRed, "Attempt", service, "on host", host, "port", port, "with password", pass, getConResultString(con_result, retrying, delayTime))
		} else {
			PrintlnColored(pterm.FgRed, "Attempt", service, "on host", host, "port", port, "with username", user, "and password", pass, getConResultString(con_result, retrying, delayTime))
		}
	}
}

func PrintWarningBeta(service string) {
	PrintlnColored(pterm.BgYellow, "Warning, the module", service, "is Beta, results may be inaccurate, use at your own risk")
}

func PrintSocksError(service string, err string) {
	PrintlnColored(pterm.FgRed, "Error", service, "SOCKS5 connection error, please check your SOCKS5 server. Error:", err)
}

func PrintSkipping(host string, service string, retries int, maxRetries int) {
	PrintlnColored(pterm.FgRed, "Warning, giving up on attempting", service, "on host", host, " max retries", retries, "out of", maxRetries)
}
