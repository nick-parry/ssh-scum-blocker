package main

/*
   The purpose of this project is to tail the auth.log, sniff out ips of bad
   ssh access attempts, and then block the scum with iptables.
*/

// Here is a demo of how you can tail a file with go

import (
	"fmt"
	//"github.com/hpcloud/tail"
	"os"
	"os/user"
	"time"
	//"regexp"
)

const (
	StateFile string = "/tmp/ssh-scum-blocker.state"
)

func main() {
	// Make sure we are the root user.
	u, _ := user.Current()
	if u.Uid != "0" {
		fmt.Println("You must be root to run this. Try again.")
		os.Exit(1)
	}

	// Setup the iptables chains if they are missing
	// TODO: Only do this if it hasn't been done yet. Add a validation method
	// that can figure out if it needs to be done or not.
	//setup()

	// New up a State object to keep track of everything. And put in some ips
	// that we know we don't want to block.
	s := buildIgnoreList()

	s.Save()
	time.Sleep(1 * time.Second)

	/*
		t, err := tail.TailFile("/tmp/auth.log", tail.Config{Follow: true})
		if err != nil {
			fmt.Println("There was a problem opening the file.")
		}

		// Tail the auth.log file and maintain a list of block-able ips
		for line := range t.Lines {
			r, _ := regexp.Compile("Failed password|Invalid user")

			// Check for the failed attempts line pattern
			m := r.MatchString(line.Text)
			// If we found it, lets gather up the ip and hand it off to be saved.
			if m == true {
				s, _ := regexp.Compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
				ip := s.FindString(line.Text)
				if len(ip) < 3 {
					fmt.Println("The ip was to short to be valid: ", ip)
				}

			}

		}
	*/
}

// Build up a collection of ips that we do not want to ever block.
// This is done by setting the "doNotBlock" flag to true on each
func buildIgnoreList() (s *State) {
	// The list of ips that we don't want to ever block.
	safeIps := []string{
		"192.168.15.10",
		"192.168.15.5",
		"192.168.15.10",
		"192.168.15.1",
		"192.168.15.7",
		"192.168.15.17",
	}
	// The state item that we are going to return.
	s = new(State)
	// Iterate through the list and set them to not block
	for _, ip := range safeIps {
		sc := Scum{}
		sc.IP = ip
		sc.DoNotBlock = true
		s.Add(sc)
	}

	return s
}
