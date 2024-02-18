package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func CheckApiGwSslEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.2")
	/* Description:
	This control checks whether Amazon API Gateway REST API stages have SSL certificates configured. Backend systems use these certificates to authenticate that incoming requests are from API Gateway.
	*/

	// Create API Gateway client
	apigatewayClient := apigateway.NewFromConfig(cfg)

	// Check REST APIs and their stages
	log.Println("[*] Checking REST APIs and their stages for SSL certificates...")
	result := checkRestAPIsForSSL(apigatewayClient)

	return result
}

func checkRestAPIsForSSL(client *apigateway.Client) string {
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
			log.Printf("└─[+] REST API: %s (ID: %s)", aws.ToString(api.Name), aws.ToString(api.Id))
			if !checkStagesForSSL(client, api.Id) {
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
		return "NA"
	}

	if allEnabled {
		return "PASS"
	}
	return "FAIL"
}

func checkStagesForSSL(client *apigateway.Client, apiID *string) bool {
	input := &apigateway.GetStagesInput{
		RestApiId: apiID,
	}
	output, err := client.GetStages(context.TODO(), input)
	if err != nil {
		log.Printf("  └─[ERROR] Failed to get stages for REST API %s: %v", aws.ToString(apiID), err)
		return false
	}

	allStagesSecure := true
	for _, stage := range output.Item {
		log.Printf("  └─[*] Stage: %s", aws.ToString(stage.StageName))

		if stage.ClientCertificateId != nil && *stage.ClientCertificateId != "" {
			log.Printf("    └─[PASS] SSL certificate configured (ID: %s)", aws.ToString(stage.ClientCertificateId))
		} else {
			log.Printf("    └─[FAIL] SSL certificate not configured")
			allStagesSecure = false
		}
	}

	return allStagesSecure
}
