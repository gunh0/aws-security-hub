// audit/cloudfront/cloudfront_default_root_object_configured.go
package cloudfront

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func CheckCloudfrontDefaultRootObjectConfigured(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.1")
	/* Description:
	This control checks whether an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The control fails if the CloudFront distribution does not have a default root object configured.
	*/

	// Create CloudFront client with us-east-1 region
	cfg.Region = "us-east-1" // CloudFront requires us-east-1 region
	client := cloudfront.NewFromConfig(cfg)

	// Get all distributions
	distributions, err := client.ListDistributions(context.TODO(), &cloudfront.ListDistributionsInput{})
	if err != nil {
		log.Printf("[ERROR] Failed to get distributions: %v", err)
		return "NA"
	}

	if distributions.DistributionList == nil || len(distributions.DistributionList.Items) == 0 {
		log.Println("[*] No distributions found")
		return "NA"
	}

	allConfigured := true

	for _, distribution := range distributions.DistributionList.Items {
		log.Printf("[*] Checking distribution: %s", aws.ToString(distribution.Id))

		// Get distribution config
		config, err := client.GetDistribution(context.TODO(), &cloudfront.GetDistributionInput{
			Id: distribution.Id,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get distribution config for %s: %v", aws.ToString(distribution.Id), err)
			continue
		}

		if config.Distribution.DistributionConfig.DefaultRootObject == nil ||
			aws.ToString(config.Distribution.DistributionConfig.DefaultRootObject) == "" {
			log.Printf("  └─[FAIL] Default root object not configured for distribution %s", aws.ToString(distribution.Id))
			allConfigured = false
		} else {
			log.Printf("  └─[PASS] Default root object configured for distribution %s: %s",
				aws.ToString(distribution.Id),
				aws.ToString(config.Distribution.DistributionConfig.DefaultRootObject))
		}
	}

	if allConfigured {
		log.Println("[PASS] All distributions have default root object configured")
		return "PASS"
	}

	log.Println("[FAIL] One or more distributions do not have default root object configured")
	return "FAIL"
}
