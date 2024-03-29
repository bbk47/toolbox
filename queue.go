package toolbox

type Queue []interface{}

func (self *Queue) Push(x interface{}) {
	*self = append(*self, x)
}

func (self *Queue) Shift() interface{} {
	h := *self
	var el interface{}
	l := len(h)
	el, *self = h[0], h[1:l]
	// Or use this instead for a Stack
	// el, *self = h[l-1], h[0:l-1]
	return el
}

func (self *Queue) Size() int {
	h := *self
	return len(h)
}

func NewQueue() *Queue {
	return &Queue{}
}
