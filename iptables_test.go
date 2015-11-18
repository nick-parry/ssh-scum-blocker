package main

// All of the iptables related tests go here
// WARNING: These tests will flush out your existing iptables rules and
// delete the LOGGING chain before starting the tests to have a consistent
// starting point, and afterwards to prevent littering. You have been warned.

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"os"
	"os/user"
	"strings"
	"testing"
)

func init() {
	// First, do some cleaning
	cleanIPTables()
	// Now, call the base setup of iptables
	setupBaseIPTables()
}

func cleanIPTables() {
	// Do an iptables flush to clean out all the rules.
	// chain now exists
	ipt, err := iptables.New()
	if err != nil {
		log(fmt.Sprintf("Failed to new up an IPtables intance: %v", err))
	}
	err = ipt.ClearChain("filter", "LOGGING")
	if err != nil {
		log("ClearChain of LOGGING failed.")
	}

	err = ipt.ClearChain("filter", "INPUT")
	if err != nil {
		log("ClearChain of INPUT failed.")
	}

	err = ipt.DeleteChain("filter", "LOGGING")
	if err != nil {
		log("DeleteChain of LOGGING failed")
	}
}

// Test the blocking of ips
func TestBlockAndUnblock(t *testing.T) {

	// Make sure we are the root user.
	u, _ := user.Current()
	if u.Uid != "0" {
		log("You must be root to run this. Try again.")
		os.Exit(1)
	}
	// Block an ip
	ok := BlockIP("1.2.3.4")
	if ok == false {
		t.Error("Failed to block IP")
	}

	// make sure this block is in this chain
	sChain := "INPUT"
	//dChain := "LOGGING"
	// Get a new iptables interface
	ipt, err := iptables.New()
	if err != nil {
		t.Error("Failed to new up an IPtables intance:", err)
	}

	rules, err := ipt.List("filter", sChain)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Test to see if the ip we banned was in that slice
	found := false
	for _, rule := range rules {
		if strings.Contains(rule, "1.2.3.4") {
			found = true
		}
	}
	if found == false {
		t.Error("Didn't find the ip that we tried to block.")
	}

	// Now that we found it, lets delete it
	ok = UnBlockIP("1.2.3.4")
	if ok == false {
		t.Error("Failed to un block IP")
	}

	// Now that we are done testing, lets call the clean up method
	cleanIPTables()

}
