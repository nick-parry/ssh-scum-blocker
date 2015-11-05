package main

// Basic scum class to track the scum.

// The number of attempts allowed before it is deemed a problem
const maxAttempts = 5

type Scum struct {
	IP          string
	NumAttempts int32
	Blocked     bool
	DoNotBlock  bool
}
