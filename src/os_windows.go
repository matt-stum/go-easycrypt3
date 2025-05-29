//go:build windows

package main

import (
	"fmt"

	"github.com/eiannone/keyboard"
	"github.com/inconshreveable/mousetrap"
	"github.com/spf13/cobra"
)

func getExitFunc() func() {
	cobra.MousetrapHelpText = "" // this allows execution from Windows Explorer (ex. drag-n-drop). Normally preExecHook() in command_win.go would prevent this.
	return func() {
		// mousetrap comes along with cobra and is normally used to prevent execution by explorer (see above)
		// however, we can use it to detect whether we need to hold the window open with a "press x to continue" blocking prompt
		if mousetrap.StartedByExplorer() {
			fmt.Println("\nPress any key to exit.")
			keyboard.GetSingleKey() // have to use a big bloated library just to have getkey functionality. (BUT MAYBE WE CAN USE IT TO BUILD MASKED PASSWORD INPUT??)
		}
	}

}
