/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

type IndexTable[Entry any] struct {
	sync.RWMutex
	table map[uint32]Entry
}

func randUint32() (uint32, error) {
	var integer [4]byte
	_, err := rand.Read(integer[:])
	// Arbitrary endianness; both are intrinsified by the Go compiler.
	return binary.LittleEndian.Uint32(integer[:]), err
}

func (table *IndexTable[Entry]) Init() {
	table.Lock()
	defer table.Unlock()
	table.table = make(map[uint32]Entry)
}

func (table *IndexTable[Entry]) Delete(index uint32) {
	table.Lock()
	defer table.Unlock()
	delete(table.table, index)
}

func (table *IndexTable[Entry]) NewIndex() (uint32, error) {
	for attempt := 0; attempt < 1<<14; attempt++ {
		// generate random index

		index, err := randUint32()
		if err != nil {
			return index, err
		}

		// check if index used

		table.RLock()
		_, ok := table.table[index]
		table.RUnlock()
		if ok {
			continue
		}

		// check again while locked

		table.Lock()
		_, found := table.table[index]
		if found {
			table.Unlock()
			continue
		}
		table.Unlock()
		return index, nil
	}
	return 0, errors.New("failed to generate unique index")
}

func (table *IndexTable[Entry]) Lookup(id uint32) Entry {
	table.RLock()
	defer table.RUnlock()
	return table.table[id]
}
