package exectraces

import (
	"fmt"
	"testing"
)

func TestET(t *testing.T) {
	et := NewExecTraces()
	et.Insert([]uint64{1, 2, 3}, "test")

	found, diff := et.Query([]uint64{1, 2, 3})
	fmt.Printf("Found = %v, Diff = %v\n", found, diff)
}
