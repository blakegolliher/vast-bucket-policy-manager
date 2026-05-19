package main

import (
	"fmt"
	"os"

	"github.com/vastdata/vast-bucket-manager/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
