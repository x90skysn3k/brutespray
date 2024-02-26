package brute

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func BruteMongoDB(host string, port int, user, password string, timeout time.Duration) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s@%s:%d", user, password, host, port))
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return false, false
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			_ = err
		}
	}()

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return false, true
	}
	return true, true
}
