package apigateway

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

func CheckApiGwCacheEncrypted(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "APIGateway.5")
	/* Description:
	This control checks whether all methods in API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in an API Gateway REST API stage is configured to cache and the cache is not encrypted. Security Hub evaluates the encryption of a particular method only when caching is enabled for that method.
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

	allEncrypted := true

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

			if stage.CacheClusterEnabled {
				if stage.CacheClusterSize == "" {
					log.Printf("    └─[FAIL] Cache enabled but size not specified for stage %s", aws.ToString(stage.StageName))
					allEncrypted = false
					continue
				}

				// Check if cache encryption is enabled for any method
				cacheEncrypted := true
				for _, methodSetting := range stage.MethodSettings {
					if !methodSetting.CacheDataEncrypted {
						cacheEncrypted = false
						break
					}
				}

				if !cacheEncrypted {
					log.Printf("    └─[FAIL] Cache encryption is not enabled for stage %s", aws.ToString(stage.StageName))
					allEncrypted = false
				} else {
					log.Printf("    └─[PASS] Cache encryption is enabled for stage %s", aws.ToString(stage.StageName))
				}
			} else {
				log.Printf("    └─[INFO] Caching is not enabled for stage %s", aws.ToString(stage.StageName))
			}
		}
	}

	if allEncrypted {
		log.Println("[PASS] All API Gateway REST API stages with caching enabled have encryption enabled")
		return "PASS"
	} else {
		log.Println("[FAIL] One or more API Gateway REST API stages with caching enabled do not have encryption enabled")
		return "FAIL"
	}
}
