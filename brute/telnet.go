package brute

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func BruteTelnet(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, false
	}
	defer connection.Close()

	err = connection.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, false
	}

	reader := bufio.NewReader(connection)
	var serverMessage string

	//serverMessage, err := reader.ReadString('\n')
	if err != nil {
		return false, true
	}

	fmt.Fprintf(connection, "%s\n", user)

	//serverMessage, err = reader.ReadString('\n')
	if err != nil {
		return false, true
	}

	fmt.Fprintf(connection, "%s\n", password)

	serverMessage, err = reader.ReadString('\n')
	if err != nil {
		return false, true
	}

	if strings.Contains(serverMessage, "Login successful") {
		return true, true
	} else {
		return false, true
	}
}
