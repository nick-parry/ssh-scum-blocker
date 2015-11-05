package main

/* A method to track the application state. Write important data as json into
ssh-scum-blocker.state(or something)
*/

import "fmt"
import "os"
import "encoding/json"

type State struct {
	States []Scum
}

func init() {
	fmt.Println("Creating the state file.")
	CreateStateFile()
}

func CreateStateFile() bool {
	fh, _ := os.Create(StateFile)
	fh.Close()
	return true
}

// Save the states as json to a file
func (s *State) Save() bool {
	// Iterate through the states, and get the json from each of them.
	// Only strings or other basic types can be marshaled up into json.
	j, _ := json.Marshal(s.States)
	fh, err := os.OpenFile(StateFile, os.O_RDWR|os.O_APPEND, 0644)
	defer fh.Close()
	if err != nil {
		panic(err)
	}
	fh.Write(j)
	fh.Close()

	return true
}

// Add a scum to the state
func (s *State) Add(sc Scum) {
	s.States = append(s.States, sc)
}
