package main

import (
	"context"
	"fmt"
	"log"
	"os"

	apigatewayChecker "aws-security-hub/audit/apigateway"
	ec2Checker "aws-security-hub/audit/ec2"
	ecsChecker "aws-security-hub/audit/ecs"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
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
		apigatewayChecker.CheckApiGwExecutionLoggingEnabled(client.Config)
	},
}

// EC2.19
var checkRestrictedCommonPortsCmd = &cobra.Command{
	Use:     "restricted-common-ports",
	Short:   "Check EC2 security groups for unrestricted access to high-risk ports",
	Aliases: []string{"ec2.19"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		ec2Client := ec2.NewFromConfig(client.Config)
		ec2Checker.CheckSecurityGroup(ec2Client)
	},
}

// EC2.1
var checkEbsSnapshotCmd = &cobra.Command{
	Use:     "ebs-snapshot-public-restorable-check",
	Short:   "Check EBS snapshots for public restorability",
	Aliases: []string{"ec2.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		ec2Client := ec2.NewFromConfig(client.Config)
		ec2Checker.CheckEbsSnapshotPublic(ec2Client)
	},
}

// ECS.1
var checkEcsTaskDefinitionCmd = &cobra.Command{
	Use:     "ecs-task-definition-user-for-host-mode-check",
	Short:   "Amazon ECS task definitions should have secure networking modes and user definitions.",
	Aliases: []string{"ecs.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client, err := initAWSClient()
		if err != nil {
			log.Fatalf("Failed to initialize AWS client: %v", err)
		}
		ecsClient := ecs.NewFromConfig(client.Config)
		ecsChecker.ECSTaskDefinitionUserForHostModeCheck(ecsClient)
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
	rootCmd.AddCommand(checkApiGwExecutionLoggingEnabledCmd)
	rootCmd.AddCommand(checkRestrictedCommonPortsCmd)
	rootCmd.AddCommand(checkEbsSnapshotCmd)
	rootCmd.AddCommand(checkEcsTaskDefinitionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
