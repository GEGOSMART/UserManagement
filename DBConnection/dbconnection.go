package DBConnection

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connection() (*mongo.Client, context.Context) {
	// conect database
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://root:root@geosmart.wrmxv.mongodb.net/geosmart_db?retryWrites=true&w=majority"))
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Connected!")
	}
	return client, ctx
}
