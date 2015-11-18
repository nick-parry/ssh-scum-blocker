package main

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
)

// Block a given ip with iptables
// Blocking 8.8.8.8 with the LOGGING chain looks like this
// iptables -A INPUT -s 8.8.8.8/32 -j LOGGING
func BlockIP(ip string) bool {
	// Some default chain names
	sChain := "INPUT"
	dChain := "LOGGING"

	// Get a new iptables interface
	ipt, err := iptables.New()
	if err != nil {
		log(fmt.Sprintf("Failed to new up an IPtables intance. ERROR: %v", err))
		return false
	}

	// Build out the ipstring(add /32 to the end)
	ipstr := fmt.Sprintf("%s%s", ip, "/32")

	// Use the appendUnique method to put this in iptables, but only once
	err = ipt.AppendUnique("filter", sChain, "-s", ipstr, "-j", dChain)
	if err != nil {
		log(fmt.Sprintf("Failed to ban an ip(%v). ERROR: %v", ipstr, err))
		return false
	}

	// Since we made it here, we won
	return true
}

func UnBlockIP(ip string) bool {
	// Some default chain names
	sChain := "INPUT"
	dChain := "LOGGING"

	// Get a new iptables interface
	ipt, err := iptables.New()
	if err != nil {
		log(fmt.Sprintf("Failed to new up an IPtables intance. ERROR: %v", err))
		return false
	}

	// Build out the ipstring(add /32 to the end)
	ipstr := fmt.Sprintf("%s%s", ip, "/32")

	// Use the appendUnique method to put this in iptables, but only once
	err = ipt.Delete("filter", sChain, "-s", ipstr, "-j", dChain)
	if err != nil {
		log(fmt.Sprintf("Failed to ban an ip(%v). ERROR: %v", ipstr, err))
		return false
	}

	// Since we made it here, we won
	return true
}
