package main

/*
	Handle some basic sorts of logging. For now, just fancy date string printing
	to standard out. But, if we want to log to a file, it can be done here.

	TODO: Implement some sort of log levels
	TODO: Write some tests.
	TODO: Create a logging class to contain all the methods. Maybe?
*/

//import "strings"
import "fmt"
import "time"

// Print a fancy timestamp on each logline
func log(str string) {
	fmt.Println(time.Now().Format(time.RFC3339), " - ", str)
}
