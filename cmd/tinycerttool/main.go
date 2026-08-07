package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&MeshControllerCommand{}, "")
	subcommands.Register(&DemoServerCommand{}, "")
	subcommands.Register(&DemoClientCommand{}, "")
	subcommands.Register(&MakeCAPoolSecretCommand{}, "")

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
