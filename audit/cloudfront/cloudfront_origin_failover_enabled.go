// audit/cloudfront/cloudfront_origin_failover_enabled.go
package cloudfront

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func CheckCloudfrontOriginFailoverEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.4")
	/* Description:
	This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins.
	CloudFront origin failover can increase availability. Origin failover automatically redirects traffic to a secondary origin if the primary origin is unavailable or if it returns specific HTTP response status codes.
	*/

	// Create CloudFront client with us-east-1 region
	cloudfrontCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(cfg.Credentials),
	)
	if err != nil {
		log.Printf("[ERROR] Failed to create CloudFront config: %v", err)
		return "NA"
	}

	client := cloudfront.NewFromConfig(cloudfrontCfg)

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

		// Check origin groups
		originGroups := config.Distribution.DistributionConfig.OriginGroups
		if originGroups == nil || len(originGroups.Items) == 0 {
			log.Printf("  └─[FAIL] No origin groups configured for distribution %s", aws.ToString(distribution.Id))
			allConfigured = false
			continue
		}

		// Check each origin group
		hasValidFailover := false
		for _, group := range originGroups.Items {
			if group.Members != nil && len(group.Members.Items) >= 2 {
				log.Printf("  └─[PASS] Origin group %s has failover configured with %d origins",
					aws.ToString(group.Id),
					len(group.Members.Items))
				hasValidFailover = true
			} else {
				log.Printf("  └─[FAIL] Origin group %s does not have enough origins for failover (found %d, need at least 2)",
					aws.ToString(group.Id),
					len(group.Members.Items))
			}
		}

		if !hasValidFailover {
			log.Printf("  └─[FAIL] Distribution %s has no valid failover configuration", aws.ToString(distribution.Id))
			allConfigured = false
		} else {
			log.Printf("  └─[PASS] Distribution %s has valid failover configuration", aws.ToString(distribution.Id))
		}
	}

	if allConfigured {
		log.Println("[PASS] All CloudFront distributions have origin failover configured")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions do not have origin failover configured")
	return "FAIL"
}
