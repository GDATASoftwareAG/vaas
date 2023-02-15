package broadcast

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSingleSubscriber(t *testing.T) {
	ctx := context.Background()
	defer ctx.Done()
	inputChan := make(chan int)
	broadcastChannel := New(ctx, inputChan)
	sub := broadcastChannel.Subscribe()
	defer broadcastChannel.RemoveSubscription(sub)

	inputChan <- 1
	foo := <-sub

	assert.Equal(t, foo, 1)
}

func TestMultipleSubscriberRoutines(t *testing.T) {
	ctx := context.Background()
	defer ctx.Done()
	inputChan := make(chan int)
	broadcastChannel := New(ctx, inputChan)
	var subList []<-chan int
	for i := 0; i < 5; i++ {
		sub := broadcastChannel.Subscribe()
		defer broadcastChannel.RemoveSubscription(sub)
		subList = append(subList, sub)
	}
	var wg sync.WaitGroup

	for _, sub := range subList {
		wg.Add(1)
		go func(sub <-chan int) {
			defer wg.Done()
			assert.Equal(t, <-sub, 3)
		}(sub)
	}
	inputChan <- 3
	wg.Wait()
}
