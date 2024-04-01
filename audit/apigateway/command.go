// audit/apigateway/command.go
package apigateway

import (
	"aws-security-hub/types"
	"log"

	"github.com/spf13/cobra"
)

// GetCommands returns all API Gateway related commands
func GetCommands(initClient func() (*types.AWSClient, error)) []*cobra.Command {
	return []*cobra.Command{
		{
			Use:     "api-gw-execution-logging-enabled",
			Short:   "API Gateway REST and WebSocket API execution logging should be enabled",
			Aliases: []string{"apigateway.1"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwExecutionLoggingEnabled(client.Config)
				log.Printf("[APIGateway.1] %s", result)
			},
		},
		{
			Use:     "api-gw-ssl-enabled",
			Short:   "API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
			Aliases: []string{"apigateway.2"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwSslEnabled(client.Config)
				log.Printf("[APIGateway.2] %s", result)
			},
		},
		{
			Use:     "api-gw-xray-enabled",
			Short:   "API Gateway REST API stages should have AWS X-Ray tracing enabled",
			Aliases: []string{"apigateway.3"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwXrayEnabled(client.Config)
				log.Printf("[APIGateway.3] %s", result)
			},
		},
		{
			Use:     "api-gw-associated-with-waf",
			Short:   "API Gateway should be associated with a WAF Web ACL",
			Aliases: []string{"apigateway.4"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwAssociatedWithWaf(client.Config)
				log.Printf("[APIGateway.4] %s", result)
			},
		},
		{
			Use:     "api-gw-cache-encrypted",
			Short:   "API Gateway REST API cache data should be encrypted at rest",
			Aliases: []string{"apigateway.5"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwCacheEncrypted(client.Config)
				log.Printf("[APIGateway.5] %s", result)
			},
		},
		{
			Use:     "api-gwv2-authorization-type-configured",
			Short:   "API Gateway routes should specify an authorization type",
			Aliases: []string{"apigateway.8"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwv2AuthorizationTypeConfigured(client.Config)
				log.Printf("[APIGateway.8] %s", result)
			},
		},
		{
			Use:     "api-gwv2-access-logs-enabled",
			Short:   "Access logging should be configured for API Gateway V2 Stages",
			Aliases: []string{"apigateway.9"},
			Run: func(cmd *cobra.Command, args []string) {
				client, err := initClient()
				if err != nil {
					log.Fatalf("Failed to initialize AWS client: %v", err)
				}
				result := CheckApiGwv2AccessLogsEnabled(client.Config)
				log.Printf("[APIGateway.9] %s", result)
			},
		},
	}
}
