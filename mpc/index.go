package mpc

import (
	"fmt"
	"math"
)

// checkedIndexEnd returns the exclusive end of a bounded in-memory OT range.
// Keeping this arithmetic in one place prevents cumulative pool frontiers from
// wrapping while per-batch counts remain native ints.
func checkedIndexEnd(start uint64, count int) (uint64, error) {
	if count < 0 {
		return 0, fmt.Errorf("mpc: negative OT count %d", count)
	}
	distance := uint64(count)
	if distance > math.MaxUint64-start {
		return 0, fmt.Errorf("mpc: OT index range overflows uint64: start=%d count=%d", start, count)
	}
	return start + distance, nil
}

// CheckedOTIndexEnd validates cumulative OT frontier arithmetic and returns
// the exclusive end. Protocol handlers use it before publishing or mutating
// state derived from untrusted cumulative indices.
func CheckedOTIndexEnd(start uint64, count int) (uint64, error) {
	return checkedIndexEnd(start, count)
}
