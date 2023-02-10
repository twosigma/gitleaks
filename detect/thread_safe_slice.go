package detect

import (
	"sync"
)

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
func (tslice *ThreadSafeSlice[K]) Append(item K) {
	tslice.mutex.Lock()
	defer tslice.mutex.Unlock()
	tslice.slice = append(tslice.slice, item)
}

// Pop item from slice. True if Pop returned valid element
func (tslice *ThreadSafeSlice[K]) Pop() (K, bool) {
	tslice.mutex.Lock()
	defer tslice.mutex.Unlock()

	if len(tslice.slice) == 0 {
		// https://stackoverflow.com/questions/70585852/return-default-value-for-generic-type

		var zeroK K
		return zeroK, false
	}

	var item K
	item, tslice.slice = tslice.slice[0], tslice.slice[1:]

	return item, true
}
