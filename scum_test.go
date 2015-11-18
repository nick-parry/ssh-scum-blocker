package main

import "testing"

// Test the creation of a basic Scum
func TestScumHasBasicMembers(t *testing.T) {

	// New up a scum
	scum := Scum{"1.2.3.4", 4, false, false}
	scum.NumAttempts = 3

}
