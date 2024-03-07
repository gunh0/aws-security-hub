package main

import (
	"context"
	"fmt"
	"log"
	"os"

	apigatewayChecker "aws-security-hub/audit/apigateway"
	documentdbChecker "aws-security-hub/audit/documentdb"
	ec2Checker "aws-security-hub/audit/ec2"
	s3Checker "aws-security-hub/audit/s3"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AWSClient wraps the AWS SDK config
type AWSClient struct {
	Config aws.Config
}

// initAWSClient initializes a universal AWS client
func initAWSClient() (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(viper.GetString("aws_region")),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &AWSClient{Config: cfg}, nil
}

var rootCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit your AWS resources",
}

// APIGateway.1
var checkApiGwExecutionLoggingEnabledCmd = &cobra.Command{
	Use:     "api-gw-execution-logging-enabled",
	Short:   "API Gateway REST and WebSocket API execution logging should be enabled",
	Aliases: []string{"apigateway.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := apigatewayChecker.CheckApiGwExecutionLoggingEnabled(client.Config)
		// Print Result
		log.Printf("[APIGateway.1] %s", result)
	},
}

// APIGateway.2
var checkApiGwSslEnabledCmd = &cobra.Command{
	Use:     "api-gw-ssl-enabled",
	Short:   "API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
	Aliases: []string{"apigateway.2"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := apigatewayChecker.CheckApiGwSslEnabled(client.Config)
		// Print Result
		log.Printf("[APIGateway.2] %s", result)
	},
}

// APIGateway.3
var checkApiGwXrayEnabledCmd = &cobra.Command{
	Use:     "api-gw-xray-enabled",
	Short:   "API Gateway REST API stages should have AWS X-Ray tracing enabled",
	Aliases: []string{"apigateway.3"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := apigatewayChecker.CheckApiGwXrayEnabled(client.Config)
		// Print Result
		log.Printf("[APIGateway.3] %s", result)
	},
}

// APIGateway.4
var checkApiGwAssociatedWithWafCmd = &cobra.Command{
	Use:     "api-gw-associated-with-waf",
	Short:   "API Gateway should be associated with a WAF Web ACL",
	Aliases: []string{"apigateway.4"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		result := apigatewayChecker.CheckApiGwAssociatedWithWaf(client.Config)
		// Print Result
		log.Printf("[APIGateway.4] %s", result)
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

	// Add all commands to root command
	rootCmd.AddCommand(checkApiGwExecutionLoggingEnabledCmd)             // APIGateway.1
	rootCmd.AddCommand(checkApiGwSslEnabledCmd)                          // APIGateway.2
	rootCmd.AddCommand(checkApiGwXrayEnabledCmd)                         // APIGateway.3
	rootCmd.AddCommand(checkApiGwAssociatedWithWafCmd)                   // APIGateway.4
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
