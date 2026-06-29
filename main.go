// Main Brutespray Package
package main

import (
	"fmt"
	"os"

	brutespray "github.com/x90skysn3k/brutespray/v2/brutespray"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "wordlist" {
		brutespray.WordlistCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "plan" {
		os.Args = append([]string{os.Args[0], "--dry-run"}, os.Args[2:]...)
		brutespray.Execute()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		if err := brutespray.AuditCommand(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}
	brutespray.Execute()
}
