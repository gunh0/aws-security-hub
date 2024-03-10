// audit/apigateway/api_gwv2_access_logs_enabled.go
package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func CheckApiGwv2AccessLogsEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.9")
	/* Description:
	This control checks if Amazon API Gateway V2 stages have access logging configured. This control fails if access log settings aren't defined.
	*/

	// Create API Gateway V2 client
	client := apigatewayv2.NewFromConfig(cfg)

	// Get all APIs
	apis, err := client.GetApis(context.TODO(), &apigatewayv2.GetApisInput{})
	if err != nil {
		log.Printf("[ERROR] Failed to get APIs: %v", err)
		return "NA"
	}

	if len(apis.Items) == 0 {
		log.Println("[*] No APIs found")
		return "NA"
	}

	allLogsEnabled := true

	for _, api := range apis.Items {
		log.Printf("[*] Checking API: %s", aws.ToString(api.Name))

		// Get stages for each API
		stages, err := client.GetStages(context.TODO(), &apigatewayv2.GetStagesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get stages for API %s: %v", aws.ToString(api.Name), err)
			continue
		}

		for _, stage := range stages.Items {
			log.Printf("  └─[*] Checking stage: %s", aws.ToString(stage.StageName))

			if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
				log.Printf("    └─[FAIL] Access logging not configured for stage %s", aws.ToString(stage.StageName))
				allLogsEnabled = false
			} else {
				log.Printf("    └─[PASS] Access logging configured for stage %s. Destination ARN: %s",
					aws.ToString(stage.StageName), aws.ToString(stage.AccessLogSettings.DestinationArn))
			}
		}
	}

	if allLogsEnabled {
		log.Println("[PASS] All API Gateway V2 stages have access logging configured")
		return "PASS"
	} else {
		log.Println("[FAIL] One or more API Gateway V2 stages do not have access logging configured")
		return "FAIL"
	}
}
