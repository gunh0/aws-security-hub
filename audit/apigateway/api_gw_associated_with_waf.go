package apigateway

import (
	"context"
	"fmt"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func CheckApiGwAssociatedWithWaf(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.4")
	/* Description:
	This control checks whether an API Gateway stage uses an AWS WAF web access control list (ACL). This control fails if an AWS WAF web ACL is not attached to a REST API Gateway stage.
	*/

	// Create API Gateway client
	apiClient := apigateway.NewFromConfig(cfg)

	// Create WAFv2 client
	wafClient := wafv2.NewFromConfig(cfg)

	// Get all REST APIs
	apis, err := apiClient.GetRestApis(context.TODO(), &apigateway.GetRestApisInput{})
	if err != nil {
		log.Printf("[ERROR] Failed to get REST APIs: %v", err)
		return "NA"
	}

	if len(apis.Items) == 0 {
		log.Println("[*] No REST APIs found")
		return "NA"
	}

	allAssociated := true

	for _, api := range apis.Items {
		log.Printf("[*] Checking API: %s", aws.ToString(api.Name))

		// Get stages for each API
		stages, err := apiClient.GetStages(context.TODO(), &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get stages for API %s: %v", aws.ToString(api.Name), err)
			continue
		}

		for _, stage := range stages.Item {
			log.Printf("  └─[*] Checking stage: %s", aws.ToString(stage.StageName))

			// Check if the stage is associated with a WAF WebACL
			webACLs, err := wafClient.ListWebACLs(context.TODO(), &wafv2.ListWebACLsInput{
				Scope: types.ScopeRegional,
			})
			if err != nil {
				log.Printf("    └─[ERROR] Failed to list WebACLs: %v", err)
				continue
			}

			stageAssociated := false
			for _, webACL := range webACLs.WebACLs {
				resources, err := wafClient.ListResourcesForWebACL(context.TODO(), &wafv2.ListResourcesForWebACLInput{
					WebACLArn:    webACL.ARN,
					ResourceType: types.ResourceTypeApiGateway,
				})
				if err != nil {
					log.Printf("    └─[ERROR] Failed to list resources for WebACL: %v", err)
					continue
				}

				stageARN := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s",
					cfg.Region, aws.ToString(api.Id), aws.ToString(stage.StageName))

				for _, resource := range resources.ResourceArns {
					if resource == stageARN {
						stageAssociated = true
						log.Printf("    └─[PASS] Stage %s is associated with WebACL %s", aws.ToString(stage.StageName), aws.ToString(webACL.Name))
						break
					}
				}

				if stageAssociated {
					break
				}
			}

			if !stageAssociated {
				log.Printf("    └─[FAIL] Stage %s is not associated with any WebACL", aws.ToString(stage.StageName))
				allAssociated = false
			}
		}
	}

	if allAssociated {
		log.Println("[PASS] All API Gateway stages are associated with WAF WebACLs")
		return "PASS"
	} else {
		log.Println("[FAIL] One or more API Gateway stages are not associated with WAF WebACLs")
		return "FAIL"
	}
}
