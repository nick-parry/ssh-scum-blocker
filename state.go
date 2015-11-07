package main

import "strings"
import "fmt"

// The State struct contains the slice of scums that we have encountered.
type State struct {
	States []Scum
}

// Add a scum to the slice of scums
func (s *State) Add(sc Scum) {
	s.States = append(s.States, sc)
}

// Increment the attempt counter for a given scum
func (s *State) incAttempt(i int) bool {
	s.States[i].NumAttempts++
	return true
}

// Search through the slice of scums for a given ip. Return the scum, and whether
// or not it worked.
func (s *State) stateScumSearch(ip string) (scumIndex int, ok bool) {
	// Iterate through the scums and see if we find a match
	for scumIndex, scum := range s.States {
		// If it matches, lets return the scum object reference
		if scum.IP == ip {
			return scumIndex, true
		}
	}
	// If we made it all the way through the slice and didn't find anything,
	// return nil and false
	return 0, false
}

/* Check an ip and see if it needs to be blocked (return true for yes, false
 	for no).
	Return as early as possible.
	Block:
		- If this ip has been found an offensive number of times.
	Do not block:
		- If the ip matches an IP pattern to not block
		- If they have not reached the offensive number of attempts
		- If they are flagged as DoNotBlock
*/
func (s *State) CheckIP(ip string) bool {
	// See if this ip matches any of the ignore patterns
	for _, p := range ignorePatterns {
		if strings.Contains(ip, p) {
			// Do not block this if it is in the pattern
			if DEBUG == true {
				fmt.Println("IP:", ip, "Matches pattern to ignore")
			}
			return false
		}
	}

	// Do the search
	scumIndex, ok := s.stateScumSearch(ip)

	// If we didn't find this ip, then we need to new up a scum and return false
	if ok == false {
		sc := new(Scum)
		sc.IP = ip
		sc.NumAttempts = 1
		s.Add(*sc)
		if DEBUG == true {
			fmt.Println("New'd up a scum")
		}
		return false
	} else {
		// Since we found it, we need to increment the counter, and return false
		ok := s.incAttempt(scumIndex)
		if ok != true {
			fmt.Println("Failed to increment.")
		}
		if DEBUG == true {
			fmt.Println("Incremented the numAttempts to:", s.States[scumIndex].NumAttempts)
		}
	}

	// See if this ip is flagged to ignore
	if s.States[scumIndex].DoNotBlock == true {
		if DEBUG == true {
			fmt.Println("This scum is flagged to not block")
		}
		return false
	}

	// If we have tried to many times block them
	if s.States[scumIndex].NumAttempts >= maxAttempts {
		if DEBUG == true {
			fmt.Println("This scum has tried to many times. Blocking.")
		}
		return true
	}

	// If we made it here, this ip isn't ready to block yet
	if DEBUG == true {
		fmt.Println("Default is to not block IPs. Returning false.")
	}
	return false
}
