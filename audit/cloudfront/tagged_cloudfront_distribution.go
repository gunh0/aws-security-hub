// audit/cloudfront/tagged_cloudfront_distribution.go
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

func CheckTaggedCloudfrontDistribution(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.14")
	/* Description:
	A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag.
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

	allTagged := true

	for _, distribution := range distributions.DistributionList.Items {
		log.Printf("[*] Checking distribution: %s", aws.ToString(distribution.Id))

		// Get distribution details to get ARN
		distDetail, err := client.GetDistribution(context.TODO(), &cloudfront.GetDistributionInput{
			Id: distribution.Id,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get distribution details for %s: %v", aws.ToString(distribution.Id), err)
			continue
		}

		// Get distribution tags using the correct ARN
		tagsOutput, err := client.ListTagsForResource(context.TODO(), &cloudfront.ListTagsForResourceInput{
			Resource: distDetail.Distribution.ARN,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get tags for distribution %s: %v", aws.ToString(distribution.Id), err)
			continue
		}

		// Filter out system tags (starting with 'aws:')
		userTags := make(map[string]string)
		for _, tag := range tagsOutput.Tags.Items {
			if !strings.HasPrefix(aws.ToString(tag.Key), "aws:") {
				userTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}

		if len(userTags) == 0 {
			log.Printf("  └─[FAIL] No user-defined tags found for distribution %s", aws.ToString(distribution.Id))
			allTagged = false
		} else {
			log.Printf("  └─[PASS] Distribution %s has tags", aws.ToString(distribution.Id))
			// Display current tags
			log.Println("    └─[INFO] Current tags:")
			for key, value := range userTags {
				log.Printf("      └─ %s: %s", key, value)
			}
		}
	}

	if allTagged {
		log.Println("[PASS] All CloudFront distributions have at least one user-defined tag")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions have no user-defined tags")
	return "FAIL"
}
