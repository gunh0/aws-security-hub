// audit/cloudfront/cloudfront_viewer_policy_https.go
package cloudfront

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func CheckCloudfrontViewerPolicyHttps(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.3")
	/* Description:
	This control checks whether an Amazon CloudFront distribution requires viewers to use HTTPS directly or whether it uses redirection.
	The control fails if ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors.
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

	allHttps := true

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

		// Check default cache behavior
		defaultBehavior := config.Distribution.DistributionConfig.DefaultCacheBehavior
		if defaultBehavior.ViewerProtocolPolicy == types.ViewerProtocolPolicyAllowAll {
			log.Printf("  └─[FAIL] Default cache behavior allows HTTP for distribution %s", aws.ToString(distribution.Id))
			allHttps = false
		} else {
			log.Printf("  └─[PASS] Default cache behavior requires HTTPS for distribution %s (Policy: %s)",
				aws.ToString(distribution.Id),
				defaultBehavior.ViewerProtocolPolicy)
		}

		// Check additional cache behaviors
		for _, behavior := range config.Distribution.DistributionConfig.CacheBehaviors.Items {
			if behavior.ViewerProtocolPolicy == types.ViewerProtocolPolicyAllowAll {
				log.Printf("    └─[FAIL] Cache behavior for path pattern %s allows HTTP", aws.ToString(behavior.PathPattern))
				allHttps = false
			} else {
				log.Printf("    └─[PASS] Cache behavior for path pattern %s requires HTTPS (Policy: %s)",
					aws.ToString(behavior.PathPattern),
					behavior.ViewerProtocolPolicy)
			}
		}
	}

	if allHttps {
		log.Println("[PASS] All CloudFront distributions require HTTPS or redirect to HTTPS")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions allow HTTP")
	return "FAIL"
}
