package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "veronica",
	Short: "Control the Veronica daemon running inside the Lima VM",
	Long: `veronica manages the Veronica daemon that runs inside a Lima VM.

The Lima VM must be created before use:
  limactl create --name=veronica lima/veronica.yaml`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
