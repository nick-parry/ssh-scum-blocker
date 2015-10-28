package main

/******************************************************************************
   	Copyright 2015 Nick Parry

   	Licensed under the Apache License, Version 2.0 (the "License");
   	you may not use this file except in compliance with the License.
   	You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   	Unless required by applicable law or agreed to in writing, software
   	distributed under the License is distributed on an "AS IS" BASIS,
   	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   	See the License for the specific language governing permissions and
   	limitations under the License.

	The goal of this it to setup the framework to make it easy to block internet
	scum. This will setup a "LOGGING" chain that will log blocks and then drop
	all packets from that ip. In addition, this will also setup a rule in the
	"INPUT" chain to ignore icmp traffic.

	Here is what the iptables rules look like after this has been run:
	Chain LOGGING (2538 references)
	 pkts bytes target     prot opt in     out     source               destination
	 83641 5382K LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            limit: avg 5/min burst 10 LOG flags 0 level 7 prefix "Drop it like its hot: "
	  113K 7323K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0


	Setup a rule that ignores icmp requests. This rule looks like this:
	Chain INPUT (policy ACCEPT 306K packets, 68M bytes)
	 pkts bytes target     prot opt in     out     source               destination
	     2   168 LOGGING    icmp --  *      *       0.0.0.0/0            0.0.0.0/0            icmptype 8



	TODO: Allow the creation of the LOGGING chain to be optional
	TODO: Allow the creation of the icmp block to be optional
******************************************************************************/

import (
	"fmt"
	"github.com/nick-parry/go-iptables/iptables"
	"os"
	"os/user"
)

func main() {

	// Make sure we are the root user.
	u, err := user.Current()
	if u.Uid != "0" {
		fmt.Println("You must be root to run this. Try again.")
		os.Exit(1)
	}

	i, err := iptables.New()
	if err != nil {
		fmt.Println("Some stuff is broken yo.")
	}

	// The table that we are going to use(the default is filter)
	table := "filter"

	// The rule that we will add first will be for the logging chain
	chain := "LOGGING"
	// Create the chain(We don't care about errors becuase it throws one if the
	// chain already exists)
	i.NewChain(table, chain)

	// Setup the logging rule so we can log the failed attempts
	err = i.AppendUnique(table, chain, "-m", "limit", "--limit", "5/min", "--limit-burst", "10",
		"-j", "LOG", "--log-prefix", "Drop it like its hot:", "--log-level", "7")
	if err != nil {
		fmt.Printf("ERROR YO:\n%s", err)
	}
	// Setup the drop rule. This will drop all packets that make it to this chain.
	err = i.AppendUnique(table, chain, "-j", "DROP")
	if err != nil {
		fmt.Printf("ERROR YO:\n%s", err)
	}
	fmt.Println("Done adding the logging chain.")

	// Add the icmp block to the input chain
	chain = "INPUT"
	err = i.AppendUnique(table, chain, "-p", "icmp", "-m", "icmp",
		"--icmp-type", "8", "-j", "LOGGING")
	if err != nil {
		fmt.Printf("ERROR YO:\n%s", err)
	}

	/*
		// Now, lets list out the rules in the logging chain
		stuff, err := i.List(table, chain)
		fmt.Printf("Here is what the current %s looks like:\n", chain)
		for _, j := range stuff {
			fmt.Println(j)
		}
	*/

}
