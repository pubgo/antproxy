package cmds

import (
	"github.com/pubgo/antproxy/cmds/antproxy"
	"github.com/pubgo/antproxy/cmds/mkcert"
	"github.com/pubgo/antproxy/cmds/wv"
	"github.com/pubgo/antproxy/version"
	"github.com/pubgo/xcmd/xcmd"
)

// Service service name
const Service = "antproxy"

// Execute exec
var Execute = xcmd.Init(func(cmd *xcmd.Command) {
	cmd.Version = version.Version
	cmd.Use = Service

	cmd.AddCommand(
		mkcert.Init(),
		antproxy.Init(),
		wv.Init(),
	)
})
