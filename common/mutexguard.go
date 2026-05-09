package common

import "sync"

type MutexGuard[T any] struct {
	mu  sync.RWMutex
	obj T
}

func WithGuard[T any](obj T) *MutexGuard[T] {
	return &MutexGuard[T]{obj: obj}
}

func (g *MutexGuard[T]) UnsafeRead(f func(obj T)) {
	f(g.obj)
}

func (g *MutexGuard[T]) UnsafeWrite(f func(obj *T)) {
	f(&g.obj)
}

func (g *MutexGuard[T]) Read(f func(obj T)) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	f(g.obj)
}

func (g *MutexGuard[T]) Write(f func(obj *T)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(&g.obj)
}
