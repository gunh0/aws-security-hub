// audit/cloudfront/cloudfront_s3_origin_non_existent_bucket.go
package cloudfront

import (
	"context"
	"log"
	"strings"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func CheckCloudfrontS3OriginNonExistentBucket(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "CloudFront.12")
	/* Description:
	This control checks whether Amazon CloudFront distributions are pointing to non-existent Amazon S3 origins.
	The control fails for a CloudFront distribution if the origin is configured to point to a non-existent bucket.
	This control only applies to CloudFront distributions where an S3 bucket without static website hosting is the S3 origin.
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

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)
	cloudFrontClient := cloudfront.NewFromConfig(cloudfrontCfg)

	// Get all distributions
	distributions, err := cloudFrontClient.ListDistributions(context.TODO(), &cloudfront.ListDistributionsInput{})
	if err != nil {
		log.Printf("[ERROR] Failed to get distributions: %v", err)
		return "NA"
	}

	if distributions.DistributionList == nil || len(distributions.DistributionList.Items) == 0 {
		log.Println("[*] No distributions found")
		return "NA"
	}

	allOriginsExist := true

	for _, distribution := range distributions.DistributionList.Items {
		log.Printf("[*] Checking distribution: %s", aws.ToString(distribution.Id))

		// Get distribution config
		config, err := cloudFrontClient.GetDistribution(context.TODO(), &cloudfront.GetDistributionInput{
			Id: distribution.Id,
		})
		if err != nil {
			log.Printf("  └─[ERROR] Failed to get distribution config for %s: %v", aws.ToString(distribution.Id), err)
			continue
		}

		// Check each origin
		for _, origin := range config.Distribution.DistributionConfig.Origins.Items {
			// Check if this is an S3 origin (not a website endpoint)
			domainName := aws.ToString(origin.DomainName)
			if !strings.Contains(domainName, ".s3.") || strings.Contains(domainName, ".s3-website-") {
				log.Printf("  └─[INFO] Origin %s is not an S3 bucket origin, skipping", aws.ToString(origin.Id))
				continue
			}

			// Extract bucket name from domain
			bucketName := strings.Split(domainName, ".s3.")[0]
			log.Printf("  └─[*] Checking S3 bucket origin: %s", bucketName)

			// Check if bucket exists
			_, err := s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
				Bucket: aws.String(bucketName),
			})

			if err != nil {
				log.Printf("    └─[FAIL] S3 bucket %s does not exist or is not accessible", bucketName)
				allOriginsExist = false
			} else {
				log.Printf("    └─[PASS] S3 bucket %s exists and is accessible", bucketName)
			}
		}
	}

	if allOriginsExist {
		log.Println("[PASS] All CloudFront distributions point to existing S3 buckets")
		return "PASS"
	}

	log.Println("[FAIL] One or more CloudFront distributions point to non-existent S3 buckets")
	return "FAIL"
}
