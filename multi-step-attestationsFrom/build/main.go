// Tiny throw-away program used by the multi-step-attestationsFrom example.
//
// The dependency on github.com/google/uuid is deliberate: it forces a
// non-empty go.sum, gives syft something to enumerate as an SBOM
// component, and makes the build's product Merkle root depend on a real
// downloaded module — not just the local source tree.
package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	fmt.Printf("hello-multi-step build, run id=%s\n", uuid.New())
}
