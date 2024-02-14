package main

import (
	"context"
	"fmt"
	"log"
	"os"

	ec2Checker "aws-security-hub/audit/ec2"
	ecsChecker "aws-security-hub/audit/ecs"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Initialize the AWS SDK EC2 client
func InitAwsClient() *ec2.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(viper.GetString("aws_region")), // Use Viper to get the region
	)
	if err != nil {
		log.Fatalf("[-] Unable to load SDK config, %v", err)
	}

	return ec2.NewFromConfig(cfg)
}

// Initialize the AWS SDK ECS client (can be reused if needed)
func InitEcsClient() *ecs.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(viper.GetString("aws_region")), // Use Viper to get the region
	)
	if err != nil {
		log.Fatalf("[-] Unable to load SDK config, %v", err)
	}

	return ecs.NewFromConfig(cfg)
}

var rootCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit your AWS resources",
}

var checkRestrictedCommonPortsCmd = &cobra.Command{
	Use:     "restricted-common-ports",
	Short:   "Check EC2 security groups for unrestricted access to high-risk ports",
	Aliases: []string{"ec2.19"},
	Run: func(cmd *cobra.Command, args []string) {
		client := InitAwsClient()
		ec2Checker.CheckSecurityGroup(client)
	},
}

var checkEbsSnapshotCmd = &cobra.Command{
	Use:     "ebs-snapshot-public-restorable-check",
	Short:   "Check EBS snapshots for public restorability",
	Aliases: []string{"ec2.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client := InitAwsClient()
		ec2Checker.CheckEbsSnapshotPublic(client)
	},
}

var checkEcsTaskDefinitionCmd = &cobra.Command{
	Use:     "ecs-task-definition-user-for-host-mode-check",
	Short:   "Amazon ECS task definitions should have secure networking modes and user definitions.",
	Aliases: []string{"ecs.1"},
	Run: func(cmd *cobra.Command, args []string) {
		client := InitEcsClient()
		ecsChecker.ECSTaskDefinitionUserForHostModeCheck(client)
	},
}

func init() {
	// Set default AWS region to South Korea (ap-northeast-2)
	viper.SetDefault("aws_region", "ap-northeast-2") // Set default region to ap-northeast-2 (South Korea)

	viper.BindEnv("aws_access_key_id")
	viper.BindEnv("aws_secret_access_key")
	viper.BindEnv("aws_region")

	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("[*] No config file found, using environment variables.\n")
	}

	// Add EC2 related commands
	rootCmd.AddCommand(checkRestrictedCommonPortsCmd)
	rootCmd.AddCommand(checkEbsSnapshotCmd)

	// Add ECS related commands
	rootCmd.AddCommand(checkEcsTaskDefinitionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
