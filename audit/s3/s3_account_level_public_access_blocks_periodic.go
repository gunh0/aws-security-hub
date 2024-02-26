package s3

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func CheckS3AccountLevelPublicAccessBlocksPeriodic(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "S3.1")

	// Create S3 client
	client := s3.NewFromConfig(cfg)

	// List buckets
	listBucketsOutput, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		log.Printf("└─[ERROR] Failed to list S3 buckets: %v", err)
		return "NA"
	}

	if len(listBucketsOutput.Buckets) == 0 {
		log.Println("└─[*] No S3 buckets found")
		return "NA"
	}

	allBucketsCompliant := true

	for _, bucket := range listBucketsOutput.Buckets {
		log.Printf("└─[*] Checking bucket: %s", *bucket.Name)

		publicAccessBlockOutput, err := client.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			log.Printf("  └─[ERROR] Failed to get public access block for bucket %s: %v", *bucket.Name, err)
			allBucketsCompliant = false
			continue
		}

		if publicAccessBlockOutput.PublicAccessBlockConfiguration == nil {
			log.Printf("  └─[FAIL] Public access block not configured for bucket %s", *bucket.Name)
			allBucketsCompliant = false
			continue
		}

		config := publicAccessBlockOutput.PublicAccessBlockConfiguration

		log.Println("  └─[*] Public Access Block Configuration:")
		log.Printf("    └─[%s] Block new public ACLs: %t", getStatus(config.BlockPublicAcls), *config.BlockPublicAcls)
		log.Printf("    └─[%s] Block public access via any ACLs: %t", getStatus(config.IgnorePublicAcls), *config.IgnorePublicAcls)
		log.Printf("    └─[%s] Block new public bucket policies: %t", getStatus(config.BlockPublicPolicy), *config.BlockPublicPolicy)
		log.Printf("    └─[%s] Block public and cross-account access via any bucket policy: %t", getStatus(config.RestrictPublicBuckets), *config.RestrictPublicBuckets)

		if !*config.BlockPublicAcls || !*config.IgnorePublicAcls || !*config.BlockPublicPolicy || !*config.RestrictPublicBuckets {
			allBucketsCompliant = false
		}
	}

	if allBucketsCompliant {
		log.Println("└─[PASS] All S3 buckets have appropriate public access block settings")
		return "PASS"
	} else {
		log.Println("└─[FAIL] One or more S3 buckets do not have appropriate public access block settings")
		return "FAIL"
	}
}

func getStatus(value *bool) string {
	if *value {
		return "PASS"
	}
	return "FAIL"
}
