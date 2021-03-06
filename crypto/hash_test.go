// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package crypto

import (
	"reflect"
	"testing"
)

// test RIPEMD160 hash
func TestRipemd160(t *testing.T) {
	// empty string
	expectDigest := []byte{156, 17, 133, 165, 197, 233, 252, 84, 97, 40, 8, 151, 126, 232, 245, 72, 178, 37, 141, 49}
	emptyStringDigest := Ripemd160([]byte(""))
	if !reflect.DeepEqual(emptyStringDigest, expectDigest) {
		t.Errorf("Ripemd160 digest = %v, expects %v", emptyStringDigest, expectDigest)
	}
}

// test SHA256 hash
func TestSha256(t *testing.T) {
	// empty string
	expectDigest := []byte{227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85}
	emptyStringDigest := Sha256([]byte(""))
	if !reflect.DeepEqual(emptyStringDigest, expectDigest) {
		t.Errorf("Sha256 digest = %v, expects %v", emptyStringDigest, expectDigest)
	}
}
