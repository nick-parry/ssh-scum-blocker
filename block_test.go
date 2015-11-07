package main

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"os"
	"os/user"
	"strings"
	"testing"
)

// Test the blocking of ips
func TestBlock(t *testing.T) {

	// Make sure we are the root user.
	u, _ := user.Current()
	if u.Uid != "0" {
		fmt.Println("You must be root to run this. Try again.")
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

}
