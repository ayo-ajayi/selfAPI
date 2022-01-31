package mongodb

import (
	"context"
	"log"
	"time"

	"github.com/ayo-ajayi/selfGin/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var _, mongo_url, _ = config.Config("", "MONGODB_URL", "ACCESS_SECRET")

func Init()(*mongo.Collection, *mongo.Collection, *mongo.Collection){
	client, err := mongo.NewClient(options.Client().ApplyURI(mongo_url))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
		return nil, nil, nil
	}
	log.Println("MongoDB connection successful")


	return client.Database("selfgin").Collection("Tokens"), client.Database("selfgin").Collection("Users"), client.Database("selfgin").Collection("Todos")
}