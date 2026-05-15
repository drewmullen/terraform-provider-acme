package main

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/vancluever/terraform-provider-acme/v2/acme"
	"github.com/vancluever/terraform-provider-acme/v2/acme/dnsplugin"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == dnsplugin.PluginArg {
		dnsplugin.Serve()
		return
	}

	initLegoLogger()

	ctx := context.Background()
	muxServer, err := tf5muxserver.NewMuxServer(ctx,
		providerserver.NewProtocol5(acme.NewFrameworkProvider()),
		acme.Provider().GRPCProvider,
	)
	if err != nil {
		panic(err)
	}

	plugin.Serve(&plugin.ServeOpts{
		GRPCProviderFunc: muxServer.ProviderServer,
	})
}
