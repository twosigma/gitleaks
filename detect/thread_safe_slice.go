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

func (tslice *ThreadSafeSlice[K]) append(item K) {
	tslice.mutex.Lock()
	tslice.slice = append(tslice.slice, item)
	tslice.mutex.Unlock()
}
