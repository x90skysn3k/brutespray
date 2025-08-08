package brute

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/x90skysn3k/brutespray/v2/modules"
)

type ContextDialerWrapper struct {
	CM *modules.ConnectionManager
}

func (cdw *ContextDialerWrapper) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); ok {

		return cdw.CM.DialFunc(network, address)
	}
	return cdw.CM.DialFunc(network, address)
}

func BruteMongoDB(host string, port int, user, password string, timeout time.Duration, socks5 string, netInterface string) (bool, bool) {
	cm, err := modules.NewConnectionManager(socks5, timeout, netInterface)
	if err != nil {
		//fmt.Printf("Failed to create connection manager: %v\n", err)
		return false, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &ContextDialerWrapper{CM: cm}

	clientOptions := options.Client().
		ApplyURI(fmt.Sprintf("mongodb://%s:%s@%s:%d", user, password, host, port)).
		SetDialer(dialer)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		//fmt.Printf("Failed to connect: %v\n", err)
		return false, false
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			_ = err
			//fmt.Printf("Failed to disconnect: %v\n", err)
		}
	}()

	err = client.Database("admin").RunCommand(ctx, map[string]interface{}{"ping": 1}).Err()
	if err != nil {
		if mongo.IsTimeout(err) {
			//fmt.Printf("Connection timeout: %v\n", err)
			return false, false
		}
		if isAuthError(err) {
			//fmt.Printf("Authentication failed: %v\n", err)
			return false, true
		}
		//fmt.Printf("Other error during ping: %v\n", err)
		return false, true
	}

	//fmt.Println("Authentication successful.")
	return true, true
}

func isAuthError(err error) bool {
	if commandError, ok := err.(mongo.CommandError); ok {
		authErrorCodes := map[int32]bool{
			18:   true, // Authentication failed
			13:   true, // Unauthorized
			8000: true, // SaslAuthenticationFailed
		}
		return authErrorCodes[commandError.Code]
	}
	if writeException, ok := err.(mongo.WriteException); ok {
		for _, we := range writeException.WriteErrors {
			if we.Code == 18 || we.Code == 13 || we.Code == 8000 {
				return true
			}
		}
	}
	return false
}
