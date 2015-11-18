package main

import "testing"

// Turn debug off on these tests
func init() {
	DEBUG = false
}

//func (s *State) stateScumSearch(ip string) (scum *Scum, ok bool) {
// test the stateScumSearch method to make sure it is legit
func TestStateScumSearch(t *testing.T) {
	// Lets create a state and put some scum in it to search for it
	ips := []string{"8.8.8.8", "8.8.4.4"}

	s := new(State)
	// Iterate through the list and set them to not block
	for _, ip := range ips {
		sc := Scum{}
		sc.IP = ip
		sc.DoNotBlock = true
		s.Add(sc)
	}

	// Do the search that should work
	scumIndex, ok := s.stateScumSearch("8.8.8.8")
	if ok != true {
		t.Error(
			"Expected ok to be true, got", ok,
			"For scumIndex index:", scumIndex,
		)
	}

	// Do the search that should find nothing
	scumIndex, ok = s.stateScumSearch("192.168.15.10")
	if ok != false {
		t.Error(
			"Expected ok to be false, got", ok,
			"Expected nil, got:", scumIndex,
		)
	}
}

//func (s *State) CheckIP(ip string) {
// Test the check ip method
func TestCheckIP(t *testing.T) {
	// Create a state with some scums to test against
	ips := []string{"8.8.8.8", "8.8.4.4"}
	s := new(State)
	for _, ip := range ips {
		sc := Scum{}
		sc.IP = ip
		s.Add(sc)
	}

	// Test that we block if an ip has the limit of attempts
	s.States[0].NumAttempts = maxAttempts
	_, ok := s.CheckIP("8.8.8.8")
	if ok == false {
		t.Error("TestCheckIP: expected: true, got: ", ok)
	}

	// Test to see if we can block one with not enough requests
	s.States[1].NumAttempts = (maxAttempts - 2)
	_, ok = s.CheckIP("8.8.4.4")
	if ok == true {
		t.Error("TestCheckIP: expected: false, got: ", ok)
	}

	// Test to see if we can block one that is marked as do not block
	s.States[1].DoNotBlock = true
	_, ok = s.CheckIP("8.8.4.4")
	if ok == true {
		t.Error("TestCheckIP: expected: false, got: ", ok)
	}

	// Do not block something if an ip matches an ignore pattern
	// NOTE: This matches the default lan ip prefix that the ignorePatterns
	// defaults to.
	_, ok = s.CheckIP("192.168.15.5")
	if ok == true {
		t.Error("TestCheckIP: expected: false, got: ", ok)
	}

}
