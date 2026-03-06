// Main Brutespray Package
package main

import (
	"os"

	brutespray "github.com/x90skysn3k/brutespray/v2/brutespray"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "wordlist" {
		brutespray.WordlistCommand(os.Args[2:])
		return
	}
	brutespray.Execute()
}
