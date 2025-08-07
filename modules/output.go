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
		// SUCCESS - Always show these
		if service == "vnc" {
			PrintlnColored(pterm.BgGreen, "✓ SUCCESS:", service, "on", host, "port", port, "with password", pass)
			content := fmt.Sprintf("Attempt %s SUCCESS on host %s port %d with password %s %s\n", service, host, port, pass, getResultString(result))
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		} else {
			PrintlnColored(pterm.BgGreen, "✓ SUCCESS:", service, "on", host, "port", port, "with", user+":"+pass)
			content := fmt.Sprintf("Attempt %s SUCCESS on host %s port %d with username %s and password %s %s\n", service, host, port, user, pass, getResultString(result))
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		}
	} else if !result && con_result {
		// Authentication failed but connection succeeded - only show in verbose mode or for specific cases
		// For now, we'll suppress these to keep output clean
		// Uncomment the lines below if you want to see failed auth attempts
		/*
		if service == "vnc" {
			PrintlnColored(pterm.FgLightRed, "✗ FAILED:", service, "on", host, "port", port, "with password", pass)
		} else {
			PrintlnColored(pterm.FgLightRed, "✗ FAILED:", service, "on", host, "port", port, "with", user+":"+pass)
		}
		*/
	} else if !result && !con_result {
		// Connection failed - only show retry messages, not every attempt
		if retrying {
			if service == "vnc" {
				PrintlnColored(pterm.FgRed, "⚠ RETRY:", service, "on", host, "port", port, "with password", pass, "-", getConResultString(con_result, retrying, delayTime))
			} else {
				PrintlnColored(pterm.FgRed, "⚠ RETRY:", service, "on", host, "port", port, "with", user+":"+pass, "-", getConResultString(con_result, retrying, delayTime))
			}
		}
		// Suppress individual failed connection attempts to keep output clean
	}
}

func PrintWarningBeta(service string) {
	PrintlnColored(pterm.BgYellow, "⚠ Warning:", service, "is Beta, results may be inaccurate")
}

func PrintSocksError(service string, err string) {
	PrintlnColored(pterm.FgRed, "✗ SOCKS5 Error:", service, "-", err)
}

func PrintSkipping(host string, service string, retries int, maxRetries int) {
	PrintlnColored(pterm.FgRed, "⚠ SKIPPING:", service, "on", host, "after", retries, "retries")
}
