package detect

import "sync"

type ThreadSafeSlice[C any] struct {
	mutex sync.Mutex
	slice []C
}

func NewThreadSafeSlice[K any](slice []K) ThreadSafeSlice[K] {
	return ThreadSafeSlice[K]{
		mutex: sync.Mutex{},
		slice: slice,
	}
}

// Append item to slice
func (tslice *ThreadSafeSlice[K]) append(item K) {
	tslice.mutex.Lock()
	tslice.slice = append(tslice.slice, item)
	tslice.mutex.Unlock()
}

// Pop item from slice
func (tslice *ThreadSafeSlice[K]) pop() K {
	tslice.mutex.Lock()
	var item K
	item, tslice.slice = tslice.slice[0], tslice.slice[1:]
	tslice.mutex.Unlock()

	return item
}
