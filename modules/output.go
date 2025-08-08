package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pterm/pterm"
)

// NoColorMode controls whether colored output is disabled
var NoColorMode bool

// PrintlnColored prints a colored message with newline
func PrintlnColored(color pterm.Color, msg string) {
	if NoColorMode {
		fmt.Println(msg)
	} else {
		pterm.Println(pterm.NewStyle(color).Sprint(msg))
	}
}

// PrintfColored prints a formatted colored message
func PrintfColored(color pterm.Color, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if NoColorMode {
		fmt.Print(msg)
	} else {
		pterm.Print(pterm.NewStyle(color).Sprint(msg))
	}
}

func getResultString(result bool) string {
	if result {
		return "succeeded"
	} else {
		return "failed"
	}
}

func getConResultString(con_result bool, retrying bool, delayTime time.Duration) string {
	var delaying bool
	if delayTime > 2*time.Second {
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
	var msg string
	var color pterm.Color

	if result && con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, "SUCCESS")
			color = pterm.BgGreen
			content := fmt.Sprintf("[%s] %s:%d - Password '%s' - %s\n", service, host, port, pass, "SUCCESS")
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, "SUCCESS")
			color = pterm.BgGreen
			content := fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s\n", service, host, port, user, pass, "SUCCESS")
			err := WriteToFile(service, content, port, output)
			if err != nil {
				fmt.Println("write file error:", err)
			}
		}
	} else if !result && con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, "FAILED")
			color = pterm.FgLightRed
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, "FAILED")
			color = pterm.FgLightRed
		}
	} else if !result && !con_result {
		if service == "vnc" {
			msg = fmt.Sprintf("[%s] %s:%d - Password '%s' - %s", service, host, port, pass, getConResultString(con_result, retrying, delayTime))
			color = pterm.FgRed
		} else {
			msg = fmt.Sprintf("[%s] %s:%d - User '%s' - Pass '%s' - %s", service, host, port, user, pass, getConResultString(con_result, retrying, delayTime))
			color = pterm.FgRed
		}
	}

	pterm.Println(pterm.NewStyle(color).Sprint(msg))
}

func PrintWarningBeta(service string) {
	pterm.Println(pterm.NewStyle(pterm.BgYellow).Sprint(fmt.Sprintf("[!] Warning: %s module is in Beta - results may be inaccurate", service)))
}

func PrintSocksError(service string, err string) {
	pterm.Println(pterm.NewStyle(pterm.FgRed).Sprint(fmt.Sprintf("[!] Error: %s SOCKS5 connection failed - %s", service, err)))
}

func PrintSkipping(host string, service string, retries int, maxRetries int) {
	pterm.Println(pterm.NewStyle(pterm.FgRed).Sprint(fmt.Sprintf("[!] Warning: Skipping %s on %s - max retries (%d/%d) reached", service, host, retries, maxRetries)))
}
