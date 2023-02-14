package broadcast_channel

import (
	"context"
)

type IBroadcastChannel[T any] interface {
	Serve(ctx context.Context)
	Subscribe()
	RemoveSubscription(subscription <-chan T)
}

type BroadcastChannel[T any] struct {
	input            <-chan T
	subscribers      []chan T
	addSubscriber    chan chan T
	removeSubscriber chan (<-chan T)
}

func New[T any](ctx context.Context, input <-chan T) *BroadcastChannel[T] {
	b := BroadcastChannel[T]{
		input:            input,
		subscribers:      make([]chan T, 0),
		addSubscriber:    make(chan chan T),
		removeSubscriber: make(chan (<-chan T)),
	}

	go b.Serve(ctx)

	return &b
}

func (b *BroadcastChannel[T]) Serve(ctx context.Context) {
	defer func() {
		for _, subscriber := range b.subscribers {
			if subscriber != nil {
				close(subscriber)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case newSubscriber := <-b.addSubscriber:
			b.subscribers = append(b.subscribers, newSubscriber)
		case unsubscriber := <-b.removeSubscriber:
			for i, subscriber := range b.subscribers {
				if subscriber == unsubscriber {
					subCount := len(b.subscribers) - 1
					b.subscribers[i] = b.subscribers[subCount]
					b.subscribers[subCount] = make(chan T)
					b.subscribers = b.subscribers[:subCount]
				}
			}
		case val, ok := <-b.input:
			if !ok {
				return
			}
			for _, subscriber := range b.subscribers {
				if subscriber != nil {
					select {
					case subscriber <- val:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}
}

func (b *BroadcastChannel[T]) Subscribe() <-chan T {
	newSubscriber := make(chan T)
	b.addSubscriber <- newSubscriber
	return newSubscriber
}

func (b *BroadcastChannel[T]) RemoveSubscription(subscription <-chan T) {
	b.removeSubscriber <- subscription
}
