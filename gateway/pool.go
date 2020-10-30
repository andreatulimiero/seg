/*
Copyright (c) 2020, ETH and Andrea Tulimiero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package gateway

import (
	"sync"
)

type memPool struct {
	pool  [][]byte
	mutex sync.Mutex
}

func newMemPool(itemSize int, items int) *memPool {
	memPool := &memPool{pool: make([][]byte, items)}
	for i := 0; i < items; i++ {
		memPool.pool[i] = make([]byte, itemSize)
	}
	return memPool
}

func (m *memPool) get() []byte {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	poolSize := len(m.pool)
	if poolSize == 0 {
		return nil
	}
	buf := m.pool[poolSize-1]
	m.pool = m.pool[:poolSize-1]
	return buf
}

func (m *memPool) put(buf []byte) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.pool = append(m.pool, buf)
}
