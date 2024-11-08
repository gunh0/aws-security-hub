package main

import (
	"context"
	"fmt"
	"log"
	"os"

	accountAudit "aws-security-hub/audit/account"
	apigatewayAudit "aws-security-hub/audit/apigateway"
	cloudfrontChecker "aws-security-hub/audit/cloudfront"
	documentdbChecker "aws-security-hub/audit/documentdb"
	ec2Checker "aws-security-hub/audit/ec2"
	s3Checker "aws-security-hub/audit/s3"
	"aws-security-hub/types"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func initAWSClient() (*types.AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(viper.GetString("aws_region")),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &types.AWSClient{Config: cfg}, nil
}

var rootCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit your AWS resources",
}

// CloudFront.1
var checkCloudfrontDefaultRootObjectConfiguredCmd = &cobra.Command{
	Use:     "cloudfront-default-root-object-configured",
	Short:   "CloudFront distributions should have a default root object configured",
	Aliases: []string{"cloudfront.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontDefaultRootObjectConfigured(client.Config)
		// Print Result
		log.Printf("[CloudFront.1] %s", result)
	},
}

// CloudFront.3
var checkCloudfrontViewerPolicyHttpsCmd = &cobra.Command{
	Use:     "cloudfront-viewer-policy-https",
	Short:   "CloudFront distributions should require encryption in transit",
	Aliases: []string{"cloudfront.3"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontViewerPolicyHttps(client.Config)
		// Print Result
		log.Printf("[CloudFront.3] %s", result)
	},
}

// CloudFront.4
var checkCloudfrontOriginFailoverEnabledCmd = &cobra.Command{
	Use:     "cloudfront-origin-failover-enabled",
	Short:   "CloudFront distributions should have origin failover enabled",
	Aliases: []string{"cloudfront.4"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontOriginFailoverEnabled(client.Config)
		// Print Result
		log.Printf("[CloudFront.4] %s", result)
	},
}

// CloudFront.5
var checkCloudfrontAccesslogsEnabledCmd = &cobra.Command{
	Use:     "cloudfront-accesslogs-enabled",
	Short:   "CloudFront distributions should have access logging enabled",
	Aliases: []string{"cloudfront.5"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontAccesslogsEnabled(client.Config)
		// Print Result
		log.Printf("[CloudFront.5] %s", result)
	},
}

// CloudFront.12
var checkCloudfrontS3OriginNonExistentBucketCmd = &cobra.Command{
	Use:     "cloudfront-s3-origin-non-existent-bucket",
	Short:   "CloudFront distributions should not point to non-existent S3 origins",
	Aliases: []string{"cloudfront.12"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontS3OriginNonExistentBucket(client.Config)
		// Print Result
		log.Printf("[CloudFront.12] %s", result)
	},
}

// CloudFront.13
var checkCloudfrontS3OriginAccessControlEnabledCmd = &cobra.Command{
	Use:     "cloudfront-s3-origin-access-control-enabled",
	Short:   "CloudFront distributions should use origin access control",
	Aliases: []string{"cloudfront.13"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := cloudfrontChecker.CheckCloudfrontS3OriginAccessControlEnabled(client.Config)
		// Print Result
		log.Printf("[CloudFront.13] %s", result)
	},
}

// CloudFront.14
var checkTaggedCloudfrontDistributionCmd = &cobra.Command{
	Use:     "tagged-cloudfront-distribution",
	Short:   "CloudFront distributions should be tagged",
	Aliases: []string{"cloudfront.14"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}

		result := cloudfrontChecker.CheckTaggedCloudfrontDistribution(client.Config)
		// Print Result
		log.Printf("[CloudFront.14] %s", result)
	},
}

// DocumentDB.1
var checkDocdbClusterEncryptedCmd = &cobra.Command{
	Use:     "docdb-cluster-encrypted",
	Short:   "Amazon DocumentDB clusters should be encrypted at rest",
	Aliases: []string{"documentdb.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := documentdbChecker.CheckDocdbClusterEncrypted(client.Config)
		// Print Result
		log.Printf("[DocumentDB.1] %s", result)
	},
}

// DocumentDB.2
var checkDocdbClusterBackupRetentionCheckCmd = &cobra.Command{
	Use:     "docdb-cluster-backup-retention-check",
	Short:   "Amazon DocumentDB clusters should have an adequate backup retention period",
	Aliases: []string{"documentdb.2"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := documentdbChecker.CheckDocdbClusterBackupRetentionCheck(client.Config)
		// Print Result
		log.Printf("[DocumentDB.2] %s", result)
	},
}

// DocumentDB.3
var checkDocdbClusterSnapshotPublicProhibitedCmd = &cobra.Command{
	Use:     "docdb-cluster-snapshot-public-prohibited",
	Short:   "Amazon DocumentDB manual cluster snapshots should not be public",
	Aliases: []string{"documentdb.3"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := documentdbChecker.CheckDocdbClusterSnapshotPublicProhibited(client.Config)
		// Print Result
		log.Printf("[DocumentDB.3] %s", result)
	},
}

// DocumentDB.4
var CheckDocdbClusterAuditLoggingEnabledCmd = &cobra.Command{
	Use:     "docdb-cluster-audit-logging-enabled",
	Short:   "Amazon DocumentDB clusters should publish audit logs to Amazon CloudWatch Logs",
	Aliases: []string{"documentdb.4"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := documentdbChecker.CheckDocdbClusterAuditLoggingEnabled(client.Config)
		// Print Result
		log.Printf("[DocumentDB.4] %s", result)
	},
}

// DocumentDB.5
var checkDocdbClusterDeletionProtectionEnabledCmd = &cobra.Command{
	Use:     "docdb-cluster-deletion-protection-enabled",
	Short:   "Amazon DocumentDB clusters should have deletion protection enabled",
	Aliases: []string{"documentdb.5"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := documentdbChecker.CheckDocdbClusterDeletionProtectionEnabled(client.Config)
		// Print Result
		log.Printf("[DocumentDB.5] %s", result)
	},
}

// EC2.1
var checkEbsSnapshotPublicRestorableCheckCmd = &cobra.Command{
	Use:     "ebs-snapshot-public-restorable-check",
	Short:   "Check EBS snapshots for public restorability",
	Aliases: []string{"ec2.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		ec2Client := ec2.NewFromConfig(client.Config)
		result := ec2Checker.CheckEbsSnapshotPublicRestorableCheck(ec2Client)
		log.Printf("[EC2.1] %s", result)
	},
}

// S3.1
var checkS3AccountLevelPublicAccessBlocksPeriodicCmd = &cobra.Command{
	Use:     "s3-account-level-public-access-blocks-periodic",
	Short:   "S3 general purpose buckets should have block public access settings enabled",
	Aliases: []string{"s3.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := s3Checker.CheckS3AccountLevelPublicAccessBlocksPeriodic(client.Config)
		log.Printf("[S3.1] %s", result)
	},
}

func init() {
	// Set default AWS region to South Korea (ap-northeast-2)
	viper.SetDefault("aws_region", "ap-northeast-2")

	viper.BindEnv("aws_access_key_id")
	viper.BindEnv("aws_secret_access_key")
	viper.BindEnv("aws_region")

	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("[*] No config file found, using environment variables.\n")
	}

	// Amazon account controls
	for _, cmd := range accountAudit.GetCommands(initAWSClient) {
		rootCmd.AddCommand(cmd)
	}
	// Amazon API Gateway controls
	for _, cmd := range apigatewayAudit.GetCommands(initAWSClient) {
		rootCmd.AddCommand(cmd)
	}
	rootCmd.AddCommand(checkCloudfrontDefaultRootObjectConfiguredCmd)    // CloudFront.1
	rootCmd.AddCommand(checkCloudfrontViewerPolicyHttpsCmd)              // CloudFront.3
	rootCmd.AddCommand(checkCloudfrontOriginFailoverEnabledCmd)          // CloudFront.4
	rootCmd.AddCommand(checkCloudfrontAccesslogsEnabledCmd)              // CloudFront.5
	rootCmd.AddCommand(checkCloudfrontS3OriginNonExistentBucketCmd)      // CloudFront.12
	rootCmd.AddCommand(checkCloudfrontS3OriginAccessControlEnabledCmd)   // CloudFront.13
	rootCmd.AddCommand(checkTaggedCloudfrontDistributionCmd)             // CloudFront.14
	rootCmd.AddCommand(checkDocdbClusterEncryptedCmd)                    // DocumentDB.1
	rootCmd.AddCommand(checkDocdbClusterBackupRetentionCheckCmd)         // DocumentDB.2
	rootCmd.AddCommand(checkDocdbClusterSnapshotPublicProhibitedCmd)     // DocumentDB.3
	rootCmd.AddCommand(CheckDocdbClusterAuditLoggingEnabledCmd)          // DocumentDB.4
	rootCmd.AddCommand(checkDocdbClusterDeletionProtectionEnabledCmd)    // DocumentDB.5
	rootCmd.AddCommand(checkEbsSnapshotPublicRestorableCheckCmd)         // EC2.1
	rootCmd.AddCommand(checkS3AccountLevelPublicAccessBlocksPeriodicCmd) // S3.1
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
