// this file is used for fuzz testing only
package cryptoengine

import (
	"fmt"
)

func Fuzz(data []byte) int {
	_, err := MessageFromBytes(data)
	if err == nil { // means it was parsed successfully
		return 1
	}

	fmt.Printf("Error parsing emssage: %s\n", err)
	return 0
}
