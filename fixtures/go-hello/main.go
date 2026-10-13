package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd := &cobra.Command{
		Use: "go-hello",
		Run: func(*cobra.Command, []string) {
			fmt.Printf("go-hello %s (commit=%s date=%s)\n", version, commit, date)
		},
	}
	_ = cmd.Execute()
}
