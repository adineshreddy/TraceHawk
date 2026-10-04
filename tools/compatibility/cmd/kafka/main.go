package main

import (
	"context"
	"fmt"
	"github.com/twmb/franz-go/pkg/kgo"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := kgo.NewClient(kgo.SeedBrokers("127.0.0.1:19092"))
	if err != nil {
		panic(err)
	}
	defer client.Close()
	if err = client.Ping(ctx); err != nil {
		panic(err)
	}
	err = client.ProduceSync(ctx, &kgo.Record{Topic: "phase0-go", Key: []byte("probe"), Value: []byte("tracehawk-go-arm64")}).FirstErr()
	if err != nil {
		panic(err)
	}
	fmt.Println("Go producer acknowledged by Kafka")
}
