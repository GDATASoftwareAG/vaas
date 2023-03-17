package broadcast

import (
	"context"
)

type Channel[T any] interface {
	Serve(ctx context.Context)
	Subscribe() <-chan T
	RemoveSubscription(subscription <-chan T)
}

type channel[T any] struct {
	input            <-chan T
	subscribers      []chan T
	addSubscriber    chan chan T
	removeSubscriber chan (<-chan T)
}

func New[T any](ctx context.Context, input <-chan T) Channel[T] {
	c := &channel[T]{
		input:            input,
		subscribers:      make([]chan T, 0),
		addSubscriber:    make(chan chan T),
		removeSubscriber: make(chan (<-chan T)),
	}

	go c.Serve(ctx)

	return c
}

func (c *channel[T]) Serve(ctx context.Context) {
	defer func() {
		for _, subscriber := range c.subscribers {
			if subscriber != nil {
				close(subscriber)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case newSubscriber := <-c.addSubscriber:
			c.subscribers = append(c.subscribers, newSubscriber)
		case unsubscriber := <-c.removeSubscriber:
			for i, subscriber := range c.subscribers {
				if subscriber == unsubscriber {
					subCount := len(c.subscribers) - 1
					c.subscribers[i] = c.subscribers[subCount]
					c.subscribers[subCount] = make(chan T)
					c.subscribers = c.subscribers[:subCount]
					close(subscriber)
				}
			}
		case val, ok := <-c.input:
			if !ok {
				return
			}
			for _, subscriber := range c.subscribers {
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

func (c *channel[T]) Subscribe() <-chan T {
	newSubscriber := make(chan T)
	c.addSubscriber <- newSubscriber
	return newSubscriber
}

func (c *channel[T]) RemoveSubscription(subscription <-chan T) {
	c.removeSubscriber <- subscription
}
