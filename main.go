package main

/*
   The purpose of this project is to tail the auth.log, sniff out ips of bad
   ssh access attempts, and then block the scum with iptables.

   TODO: Implement some sort of command line option passing
   TODO: Use a logging frame work of sorts
   TODO: Write more tests.
*/

// Here is a demo of how you can tail a file with go

import (
	"fmt"
	"os"
	"os/user"
)

const (
	// The state file location(TODO: Use this later)
	//StateFile string = "/tmp/ssh-scum-blocker.state"
	// The number of attempts allowed before it is deemed a problem
	maxAttempts int32  = 5
	AuthLog     string = "/var/log/auth.log"
)

// TODO: get rid of all of these global vars. Command line args?
// Debug level output
var DEBUG bool = true

// A list of ip patterns that we are going to ignore
var ignorePatterns = []string{"192.168."}

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
	ok := checkIPTablesBaseConfig()
	if ok == false {
		setupBaseIPTables()
	}

	// New up a State object to keep track of everything.
	state := new(State)

	// Read the log file to harvest and process IPs
	ReadLogFile(state)

}
