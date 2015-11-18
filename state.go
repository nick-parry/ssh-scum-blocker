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
	if DEBUG == true {
		log(fmt.Sprintf("incAttempt: Incrementing the scum counter for %v to %v",
			s.States[i].IP, s.States[i].NumAttempts))
	}
	return true
}

// Search through the slice of scums for a given ip. Return the scum, and whether
// or not it worked.
func (s *State) stateScumSearch(ip string) (scumIndex int, ok bool) {
	// Iterate through the scums and see if we find a match
	for scumIndex, scum := range s.States {
		// If it matches, lets return the scum index
		if scum.IP == ip {
			if DEBUG == true {
				log(fmt.Sprintf("stateScumSearch: Found scum item for ip: %v. Returning index: %v",
					ip, scumIndex))
			}
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
func (s *State) CheckIP(ip string) (*Scum, bool) {
	// See if this ip matches any of the ignore patterns
	for _, p := range ignorePatterns {
		if strings.Contains(ip, p) {
			// Do not block this if it is in the pattern
			if DEBUG == true {
				log(fmt.Sprintf("IP: %v Matches pattern to ignore", ip))
			}
			return nil, false
		}
	}

	// Do the search
	scumIndex, ok := s.stateScumSearch(ip)

	// If we didn't find this ip, then we need to new up a scum and return false
	if ok == false {
		sc := new(Scum)
		sc.IP = ip
		sc.Blocked = false
		sc.NumAttempts = 1
		s.Add(*sc)
		if DEBUG == true {
			log(fmt.Sprintf("First time for this one. New'd up a scum for ip: %v", ip))
		}
		return sc, false
	} else {
		// Since we found it, we need check and see if it has been blocked yet.
		if s.States[scumIndex].Blocked {
			// Since this ip is already being blocked, we will do nothing and stop
			// any further processing
			if DEBUG == true {
				log(fmt.Sprintf("This scum: %v is already marked as blocked. Stopping here.", ip))
			}
			return nil, false
		} else {
			// Since it hasn't yet been blocked, we need to increment the counter, and return false
			ok := s.incAttempt(scumIndex)
			if ok != true {
				log("Failed to increment.")
			}
		}
	}

	// See if this ip is flagged to ignore
	if s.States[scumIndex].DoNotBlock == true {
		if DEBUG == true {
			log("This scum is flagged to not block")
		}
		return nil, false
	}

	// If they have tried too many times, block them
	if s.States[scumIndex].NumAttempts >= maxAttempts {
		if DEBUG == true {
			log("This scum has tried to many times. Blocking.")
		}
		return &s.States[scumIndex], true
	}

	// If we made it here, this ip isn't ready to block yet
	if DEBUG == true {
		log("Didn't meet enough criteria to block this ip. Returning false.")
	}
	return nil, false
}
