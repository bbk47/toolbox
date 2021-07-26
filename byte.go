package toolbox

import (
	"crypto/rand"
)
// get rand byte with length
func GetRandByte(len int) []byte {
	randbytes := make([]byte, len)
	rand.Read(randbytes)
	return randbytes
}