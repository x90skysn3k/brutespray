package brute

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/x90skysn3k/brutespray/modules"
)

type ContextDialerWrapper struct {
	CM *modules.ConnectionManager
}

// DialContext dials using the ConnectionManager and propagates the context
// deadline to the connection so that MongoDB operations respect timeouts (3.5 fix).
func (cdw *ContextDialerWrapper) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := cdw.CM.DialFunc(network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

func BruteMongoDB(host string, port int, user, password string, timeout time.Duration, cm *modules.ConnectionManager) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &ContextDialerWrapper{CM: cm}

	clientOptions := options.Client().
		ApplyURI(fmt.Sprintf("mongodb://%s:%s@%s:%d", user, password, host, port)).
		SetDialer(dialer)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return false, false
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			_ = err
		}
	}()

	err = client.Database("admin").RunCommand(ctx, map[string]interface{}{"ping": 1}).Err()
	if err != nil {
		if mongo.IsTimeout(err) {
			return false, false
		}
		if isAuthError(err) {
			return false, true
		}
		return false, true
	}

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
