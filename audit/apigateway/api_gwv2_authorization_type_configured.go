// audit/apigateway/api_gwv2_authorization_type_configured.go
package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func CheckApiGwv2AuthorizationTypeConfigured(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.8")
	/* Description:
	This control checks if Amazon API Gateway routes have an authorization type. The control fails if the API Gateway route doesn't have any authorization type. Optionally, you can provide a custom parameter value if you want the control to pass only if the route uses the authorization type specified in the authorizationType parameter.
	*/

	// Create API Gateway v2 client
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

	allConfigured := true
	validAuthTypes := map[string]bool{"AWS_IAM": true, "CUSTOM": true, "JWT": true}

	for _, api := range apis.Items {
		log.Printf("[*] Checking API: %s", aws.ToString(api.Name))

		// Get routes for each API
		routes, err := client.GetRoutes(context.TODO(), &apigatewayv2.GetRoutesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get routes for API %s: %v", aws.ToString(api.Name), err)
			continue
		}

		for _, route := range routes.Items {
			log.Printf("  └─[*] Checking route: %s", aws.ToString(route.RouteKey))

			if !validAuthTypes[string(route.AuthorizationType)] {
				log.Printf("    └─[FAIL] Invalid or no authorization type configured for route %s. Type: %s",
					aws.ToString(route.RouteKey), route.AuthorizationType)
				allConfigured = false
			} else {
				log.Printf("    └─[PASS] Valid authorization type %s configured for route %s",
					route.AuthorizationType, aws.ToString(route.RouteKey))
			}
		}
	}

	if allConfigured {
		log.Println("[PASS] All API Gateway routes have a valid authorization type configured (AWS_IAM, CUSTOM, or JWT)")
		return "PASS"
	} else {
		log.Println("[FAIL] One or more API Gateway routes do not have a valid authorization type configured (AWS_IAM, CUSTOM, or JWT)")
		return "FAIL"
	}
}
