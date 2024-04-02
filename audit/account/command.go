// audit/account/command.go
package account

import (
	"log"

	"aws-security-hub/types"

	"github.com/spf13/cobra"
)

// GetCommands returns all Amazon Account related commands
func GetCommands(initClient types.AWSClientInitializer) []*cobra.Command {
	return []*cobra.Command{
		{
			Use:     "security-account-information-provided",
			Short:   "Security contact information should be provided for an AWS account",
			Aliases: []string{"account.1"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckSecurityAccountInformationProvided(client.Config)
				log.Printf("[Account.1] %s", result)
			},
		},
	}
}
