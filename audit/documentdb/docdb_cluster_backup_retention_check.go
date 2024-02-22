package documentdb

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

func CheckDocdbClusterBackupRetentionCheck(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "DocumentDB.2")
	/* Description:
	This control checks whether an Amazon DocumentDB cluster has a backup retention period greater than or equal to the specified time frame. The control fails if the backup retention period is less than the specified time frame. Unless you provide a custom parameter value for the backup retention period, Security Hub uses a default value of 7 days.
	*/

	// Create DocumentDB client
	client := docdb.NewFromConfig(cfg)

	// Describe DocumentDB clusters
	log.Println("[*] Fetching DocumentDB clusters...")
	input := &docdb.DescribeDBClustersInput{}
	resp, err := client.DescribeDBClusters(context.TODO(), input)
	if err != nil {
		log.Printf("└─[ERROR] Failed to describe DocumentDB clusters: %v", err)
		return "NA"
	}

	if len(resp.DBClusters) == 0 {
		log.Println("└─[*] No DocumentDB clusters found")
		return "NA"
	}

	minRetentionPeriod := int32(7) // Default minimum retention period in days
	insufficientRetentionClusters := 0

	for _, cluster := range resp.DBClusters {
		log.Printf("└─[*] Checking cluster: %s", aws.ToString(cluster.DBClusterIdentifier))

		if cluster.BackupRetentionPeriod == nil || *cluster.BackupRetentionPeriod < minRetentionPeriod {
			log.Printf("  └─[FAIL] Cluster %s has insufficient backup retention period: %d days (minimum: %d days)",
				aws.ToString(cluster.DBClusterIdentifier),
				aws.ToInt32(cluster.BackupRetentionPeriod),
				minRetentionPeriod)
			insufficientRetentionClusters++
		} else {
			log.Printf("  └─[PASS] Cluster %s has sufficient backup retention period: %d days",
				aws.ToString(cluster.DBClusterIdentifier),
				*cluster.BackupRetentionPeriod)
		}
	}

	if insufficientRetentionClusters > 0 {
		log.Printf("└─[FAIL] %d DocumentDB clusters found with insufficient backup retention period", insufficientRetentionClusters)
		return "FAIL"
	}

	log.Println("└─[PASS] All DocumentDB clusters have sufficient backup retention period")
	return "PASS"
}
