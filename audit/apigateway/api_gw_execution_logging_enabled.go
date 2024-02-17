package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewayv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func CheckApiGwExecutionLoggingEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Fatalf("[-] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.1")

	// Create API Gateway clients
	apigatewayClient := apigateway.NewFromConfig(cfg)
	apigatewayv2Client := apigatewayv2.NewFromConfig(cfg)

	// Check REST APIs and their stages
	log.Println("[*] Checking REST APIs and their stages...")
	restResult := checkRestAPIs(apigatewayClient)

	// Check WebSocket APIs and their stages
	log.Println("[*] Checking WebSocket APIs and their stages...")
	webSocketResult := checkWebSocketAPIs(apigatewayv2Client)

	// Determine overall result
	if restResult == "NA" && webSocketResult == "NA" {
		return "NA"
	} else if restResult == "FAIL" || webSocketResult == "FAIL" {
		return "FAIL"
	} else if restResult == "PASS" && webSocketResult == "PASS" {
		return "PASS"
	}

	return "NA"
}

func checkRestAPIs(client *apigateway.Client) string {
	var position *string
	allEnabled := true
	hasAPIs := false

	for {
		input := &apigateway.GetRestApisInput{
			Limit: aws.Int32(500), // Maximum allowed value
		}
		if position != nil {
			input.Position = position
		}

		output, err := client.GetRestApis(context.TODO(), input)
		if err != nil {
			log.Printf("└─[ERROR] Failed to get REST APIs: %v", err)
			return "NA"
		}

		for _, api := range output.Items {
			hasAPIs = true
			log.Printf("└─[+] REST API: %s (ID: %s)\n", aws.ToString(api.Name), aws.ToString(api.Id))
			if !checkRestAPIStages(client, aws.ToString(api.Id)) {
				allEnabled = false
			}
		}

		if output.Position == nil {
			break
		}
		position = output.Position
	}

	if !hasAPIs {
		log.Println("└─[*] No REST APIs found")
		return "PASS" // No APIs found, so consider it as compliant
	}

	if allEnabled {
		return "PASS"
	}
	return "FAIL"
}

func checkRestAPIStages(client *apigateway.Client, apiID string) bool {
	input := &apigateway.GetStagesInput{
		RestApiId: aws.String(apiID),
	}
	output, err := client.GetStages(context.TODO(), input)
	if err != nil {
		log.Printf("  └─[ERROR] Failed to get stages for REST API %s: %v", apiID, err)
		return false
	}

	allEnabled := true
	for _, stage := range output.Item {
		log.Printf("  └─[*] Stage: %s\n", aws.ToString(stage.StageName))
		loggingEnabled := false
		for _, settings := range stage.MethodSettings {
			if settings.LoggingLevel != nil && *settings.LoggingLevel != "" && *settings.LoggingLevel != "OFF" {
				loggingEnabled = true
				log.Printf("    └─[PASS] Logging: Enabled (Level: %s)\n", *settings.LoggingLevel)
				break
			}
		}
		if !loggingEnabled {
			log.Printf("    └─[FAIL] Logging: Not enabled\n")
			allEnabled = false
		}
	}
	return allEnabled
}

func checkWebSocketAPIs(client *apigatewayv2.Client) string {
	var nextToken *string
	allEnabled := true
	hasAPIs := false

	for {
		input := &apigatewayv2.GetApisInput{
			MaxResults: aws.String("100"), // Maximum allowed value as a string
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.GetApis(context.TODO(), input)
		if err != nil {
			log.Printf("└─[ERROR] Failed to get WebSocket APIs: %v", err)
			return "NA"
		}

		for _, api := range output.Items {
			if api.ProtocolType == "WEBSOCKET" {
				hasAPIs = true
				log.Printf("└─[+] WebSocket API: %s (ID: %s)\n", aws.ToString(api.Name), aws.ToString(api.ApiId))
				if !checkWebSocketAPIStages(client, aws.ToString(api.ApiId)) {
					allEnabled = false
				}
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	if !hasAPIs {
		log.Println("└─[*] No WebSocket APIs found")
		return "PASS" // No APIs found, so consider it as compliant
	}

	if allEnabled {
		return "PASS"
	}
	return "FAIL"
}

func checkWebSocketAPIStages(client *apigatewayv2.Client, apiID string) bool {
	input := &apigatewayv2.GetStagesInput{
		ApiId: aws.String(apiID),
	}
	output, err := client.GetStages(context.TODO(), input)
	if err != nil {
		log.Printf("  └─[ERROR] Failed to get stages for WebSocket API %s: %v", apiID, err)
		return false
	}

	allEnabled := true
	for _, stage := range output.Items {
		log.Printf("  └─[*] Stage: %s\n", aws.ToString(stage.StageName))
		if stage.DefaultRouteSettings == nil || stage.DefaultRouteSettings.LoggingLevel == "OFF" {
			log.Printf("    └─[FAIL] Logging: Not enabled\n")
			allEnabled = false
		} else {
			log.Printf("    └─[PASS] Logging: Enabled (Level: %s)\n", string(stage.DefaultRouteSettings.LoggingLevel))
		}
	}
	return allEnabled
}
