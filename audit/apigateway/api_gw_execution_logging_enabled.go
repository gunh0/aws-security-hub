// audit/apigateway/api_gw_execution_logging_enabled.go
package apigateway

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func CheckApiGwExecutionLoggingEnabled(cfg aws.Config) {
	fmt.Println("[*] Checking API Gateway execution logging...")

	// Create API Gateway clients
	apigatewayClient := apigateway.NewFromConfig(cfg)
	apigatewayv2Client := apigatewayv2.NewFromConfig(cfg)

	// List REST APIs and their stages
	fmt.Println("[*] Listing REST APIs and their stages...")
	listRestAPIs(apigatewayClient)

	// List WebSocket APIs and their stages
	fmt.Println("[*] Listing WebSocket APIs and their stages...")
	listWebSocketAPIs(apigatewayv2Client)
}

func listRestAPIs(client *apigateway.Client) {
	var position *string
	for {
		input := &apigateway.GetRestApisInput{
			Limit: aws.Int32(500), // Maximum allowed value
		}
		if position != nil {
			input.Position = position
		}

		output, err := client.GetRestApis(context.TODO(), input)
		if err != nil {
			log.Printf("[-] Failed to get REST APIs: %v", err)
			return
		}

		for _, api := range output.Items {
			fmt.Printf("    [+] REST API: %s (ID: %s)\n", aws.ToString(api.Name), aws.ToString(api.Id))
			listRestAPIStages(client, aws.ToString(api.Id))
		}

		if output.Position == nil {
			break
		}
		position = output.Position
	}
}

func listRestAPIStages(client *apigateway.Client, apiID string) {
	input := &apigateway.GetStagesInput{
		RestApiId: aws.String(apiID),
	}
	output, err := client.GetStages(context.TODO(), input)
	if err != nil {
		log.Printf("        [-] Failed to get stages for REST API %s: %v", apiID, err)
		return
	}

	for _, stage := range output.Item {
		fmt.Printf("        - Stage: %s\n", aws.ToString(stage.StageName))
		loggingEnabled := false
		var loggingLevel string
		for _, settings := range stage.MethodSettings {
			if settings.LoggingLevel != nil && *settings.LoggingLevel != "" {
				loggingEnabled = true
				loggingLevel = *settings.LoggingLevel
				break
			}
		}
		if loggingEnabled {
			fmt.Printf("          Logging: Enabled (Level: %s)\n", loggingLevel)
		} else {
			fmt.Printf("          Logging: Not enabled\n")
		}
	}
}

func listWebSocketAPIs(client *apigatewayv2.Client) {
	var nextToken *string
	for {
		input := &apigatewayv2.GetApisInput{
			MaxResults: aws.String("100"), // Maximum allowed value as a string
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.GetApis(context.TODO(), input)
		if err != nil {
			log.Printf("[-] Failed to get WebSocket APIs: %v", err)
			return
		}

		for _, api := range output.Items {
			if api.ProtocolType == "WEBSOCKET" {
				fmt.Printf("    [+] WebSocket API: %s (ID: %s)\n", aws.ToString(api.Name), aws.ToString(api.ApiId))
				listWebSocketAPIStages(client, aws.ToString(api.ApiId))
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
}

func listWebSocketAPIStages(client *apigatewayv2.Client, apiID string) {
	input := &apigatewayv2.GetStagesInput{
		ApiId: aws.String(apiID),
	}
	output, err := client.GetStages(context.TODO(), input)
	if err != nil {
		log.Printf("        [-] Failed to get stages for WebSocket API %s: %v", apiID, err)
		return
	}

	for _, stage := range output.Items {
		fmt.Printf("        - Stage: %s\n", aws.ToString(stage.StageName))
		if stage.DefaultRouteSettings == nil || stage.DefaultRouteSettings.LoggingLevel == "OFF" {
			fmt.Printf("          Logging: Not enabled\n")
		} else {
			fmt.Printf("          Logging: Enabled (Level: %s)\n", string(stage.DefaultRouteSettings.LoggingLevel))
		}
	}
}
