package main

import "github.com/spf13/cobra"

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "getlicense-server",
		Short: "GetLicense API server",
		Long:  "GetLicense API server — serves the REST API and manages license lifecycle.",
		// Running without a subcommand starts the server.
		RunE:              runServe,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	cmd.AddCommand(serveCmd(), migrateCmd())
	return cmd
}
