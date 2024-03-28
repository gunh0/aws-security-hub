// audit/cloudfront/cloudfront_accesslogs_enabled.go
package cloudfront

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func CheckCloudfrontAccesslogsEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.5")
	/* Description:
	This control checks whether server access logging is enabled on CloudFront distributions. The control fails if access logging is not enabled for a distribution.
	CloudFront access logs provide detailed information about every user request that CloudFront receives. Each log contains information such as the date and time the request was received, the IP address of the viewer that made the request, the source of the request, and the port number of the request from the viewer.
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

	allLoggingEnabled := true

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

		loggingConfig := config.Distribution.DistributionConfig.Logging

		if loggingConfig == nil || !aws.ToBool(loggingConfig.Enabled) || aws.ToString(loggingConfig.Bucket) == "" {
			log.Printf("  └─[FAIL] Access logging not enabled for distribution %s", aws.ToString(distribution.Id))
			allLoggingEnabled = false
		} else {
			log.Printf("  └─[PASS] Access logging enabled for distribution %s", aws.ToString(distribution.Id))
			log.Printf("    └─[INFO] Logging destination bucket: %s", aws.ToString(loggingConfig.Bucket))
			if loggingConfig.Prefix != nil && *loggingConfig.Prefix != "" {
				log.Printf("    └─[INFO] Log file prefix: %s", aws.ToString(loggingConfig.Prefix))
			}
		}
	}

	if allLoggingEnabled {
		log.Println("[PASS] All CloudFront distributions have access logging enabled")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions do not have access logging enabled")
	return "FAIL"
}
