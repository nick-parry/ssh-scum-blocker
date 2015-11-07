package main

// Basic scum class to track the scum.

type Scum struct {
	IP          string
	NumAttempts int32
	Blocked     bool
	DoNotBlock  bool
}
