// audit/apigateway/api_gw_xray_enabled.go
package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func CheckApiGwXrayEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.3")
	/* Description:
	This control checks whether AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages.
	*/

	// Create API Gateway client
	client := apigateway.NewFromConfig(cfg)

	// Get all REST APIs
	apis, err := client.GetRestApis(context.TODO(), &apigateway.GetRestApisInput{})
	if err != nil {
		log.Printf("[ERROR] Failed to get REST APIs: %v", err)
		return "NA"
	}

	if len(apis.Items) == 0 {
		log.Println("[*] No REST APIs found")
		return "NA"
	}

	allEnabled := true

	for _, api := range apis.Items {
		log.Printf("[*] Checking API: %s", aws.ToString(api.Name))

		// Get stages for each API
		stages, err := client.GetStages(context.TODO(), &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get stages for API %s: %v", aws.ToString(api.Name), err)
			continue
		}

		for _, stage := range stages.Item {
			log.Printf("  └─[*] Checking stage: %s", aws.ToString(stage.StageName))

			if stage.TracingEnabled {
				log.Printf("    └─[PASS] X-Ray tracing enabled for stage %s", aws.ToString(stage.StageName))
			} else {
				log.Printf("    └─[FAIL] X-Ray tracing disabled for stage %s", aws.ToString(stage.StageName))
				allEnabled = false
			}
		}
	}

	if allEnabled {
		log.Println("[PASS] X-Ray tracing is enabled for all API Gateway REST API stages")
		return "PASS"
	} else {
		log.Println("[FAIL] X-Ray tracing is not enabled for one or more API Gateway REST API stages")
		return "FAIL"
	}
}
