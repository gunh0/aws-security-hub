// audit/cloudfront/cloudfront_s3_origin_access_control_enabled.go
package cloudfront

import (
	"context"
	"log"
	"strings"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func CheckCloudfrontS3OriginAccessControlEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.13")
	/* Description:
	This control checks whether an Amazon CloudFront distribution with an Amazon S3 origin has origin access control (OAC) configured. The control fails if OAC isn't configured for the CloudFront distribution.
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

	allEnabled := true
	foundS3Origin := false

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

		// Check each origin
		for _, origin := range config.Distribution.DistributionConfig.Origins.Items {
			domainName := aws.ToString(origin.DomainName)

			// Check if this is an S3 origin (not a website endpoint)
			if !strings.Contains(domainName, ".s3.") || strings.Contains(domainName, ".s3-website-") {
				continue
			}

			foundS3Origin = true
			log.Printf("  └─[*] Checking S3 origin: %s", aws.ToString(origin.Id))

			if origin.OriginAccessControlId == nil || *origin.OriginAccessControlId == "" {
				log.Printf("    └─[FAIL] Origin access control not configured for origin %s", aws.ToString(origin.Id))
				allEnabled = false
			} else {
				log.Printf("    └─[PASS] Origin access control configured (ID: %s) for origin %s",
					aws.ToString(origin.OriginAccessControlId),
					aws.ToString(origin.Id))
			}
		}
	}

	// If no S3 origins were found, return NA
	if !foundS3Origin {
		log.Println("[*] No S3 origins found in any distribution")
		return "NA"
	}

	if allEnabled {
		log.Println("[PASS] All CloudFront distributions with S3 origins have origin access control enabled")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions with S3 origins do not have origin access control enabled")
	return "FAIL"
}
