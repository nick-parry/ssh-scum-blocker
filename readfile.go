package main

import (
	"fmt"
	"github.com/hpcloud/tail"
	"regexp"
)

func ReadLogFile(state *State) {

	t, err := tail.TailFile(AuthLog, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		log("There was a problem opening the file.")
	}

	// Tail the auth.log file and inspect lines as they come in.
	for line := range t.Lines {
		// Check for the failed attempts line pattern
		r, _ := regexp.Compile("Failed password|Invalid user")
		m := r.MatchString(line.Text)

		// If we found it, lets gather up the ip and hand it off to be saved.
		if m == true {
			r, _ := regexp.Compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
			ip := r.FindString(line.Text)
			if len(ip) < 3 {
				log(fmt.Sprintf("The ip was to short to be valid: %v", ip))
			} else {
				// Does this ip need to be blocked
				scum, block := state.CheckIP(ip)
				log(fmt.Sprintf("%v to block IP: %v", block, ip))
				if block == true {
					log(fmt.Sprintf("Blocking ip: %v", ip))
					// Block this ip
					BlockIP(ip)
					// Mark this scum as being blocked
					scum.Blocked = true
				} else {
					log(fmt.Sprintf("ReadLogFile: Not blocking ip: %v", ip))
				}

			}
		}
		// Else, we will just move on since this log line has no relevance
	}

}
