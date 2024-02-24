package documentdb

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

func CheckDocdbClusterAuditLoggingEnabled(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "DocumentDB.4")
	/* Description:
	This control checks whether an Amazon DocumentDB cluster publishes audit logs to Amazon CloudWatch Logs. The control fails if the cluster doesn't publish audit logs to CloudWatch Logs.
	*/

	// Create DocumentDB client
	client := docdb.NewFromConfig(cfg)

	// Describe DocumentDB clusters
	log.Println("[*] Fetching DocumentDB clusters...")
	input := &docdb.DescribeDBClustersInput{}
	paginator := docdb.NewDescribeDBClustersPaginator(client, input)

	clustersWithoutAuditLogging := 0
	totalClusters := 0

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("└─[ERROR] Failed to describe DocumentDB clusters: %v", err)
			return "NA"
		}

		for _, cluster := range output.DBClusters {
			totalClusters++
			log.Printf("└─[*] Checking cluster: %s", aws.ToString(cluster.DBClusterIdentifier))

			auditLoggingEnabled := false
			for _, logExport := range cluster.EnabledCloudwatchLogsExports {
				if logExport == "audit" {
					auditLoggingEnabled = true
					break
				}
			}

			if !auditLoggingEnabled {
				log.Printf("  └─[FAIL] Cluster %s does not have audit logging enabled", aws.ToString(cluster.DBClusterIdentifier))
				clustersWithoutAuditLogging++
			} else {
				log.Printf("  └─[PASS] Cluster %s has audit logging enabled", aws.ToString(cluster.DBClusterIdentifier))
			}
		}
	}

	if totalClusters == 0 {
		log.Println("└─[*] No DocumentDB clusters found")
		return "NA"
	}

	if clustersWithoutAuditLogging > 0 {
		log.Printf("└─[FAIL] %d out of %d DocumentDB clusters do not have audit logging enabled", clustersWithoutAuditLogging, totalClusters)
		return "FAIL"
	}

	log.Println("└─[PASS] All DocumentDB clusters have audit logging enabled")
	return "PASS"
}
