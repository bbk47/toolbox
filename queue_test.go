package toolbox

import (
	"testing"
)

func TestQueue(t *testing.T) {

	q := NewQueue()
	q.Push(1)
	q.Push(2)
	q.Push(3)
	q.Push("L")

	s1 := q.Shift()
	if s1 != 1 || q.Size() != 3 {
		t.Error("error s1")
	}
	s2 := q.Shift()
	if s2 != 2 || q.Size() != 2 {
		t.Error("error s2")
	}
	s3 := q.Shift()
	if s3 != 3 || q.Size() != 1 {
		t.Error("error s3")
	}
	s4 := q.Shift()
	if s4 != "L" || q.Size() != 0 {
		t.Error("error s4")
	}
}
