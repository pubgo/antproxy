package main

import (
	"github.com/pubgo/antproxy/cmds"
	"github.com/pubgo/antproxy/cmds/cnst"
	"github.com/pubgo/xcmd/xcmd"
)

func main() {
	cmds.Execute(
		xcmd.WithDebug(),
		func(cmd *xcmd.Command) {
			cmd.PersistentFlags().StringP(cnst.CaRoot, "c", cnst.GetCAROOT(), "ca root dir")
		},
	)
}
