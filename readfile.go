package main

import (
	"fmt"
	"github.com/hpcloud/tail"
	"regexp"
)

func ReadLogFile(state *State) {

	t, err := tail.TailFile(AuthLog, tail.Config{Follow: true})
	if err != nil {
		fmt.Println("There was a problem opening the file.")
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
				fmt.Println("The ip was to short to be valid: ", ip)
			} else {
				// Does this ip need to be blocked
				block := state.CheckIP(ip)
				fmt.Println("Block:", block)
				if block == true {
					fmt.Println("Blocking ip:", ip)
					BlockIP(ip)
				} else {
					fmt.Println("Not blocking ip:", ip)
				}

			}
		}
		// Else, we will just move on since this log line has now relevance
	}

}
