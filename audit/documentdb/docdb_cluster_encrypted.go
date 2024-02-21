package documentdb

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

func CheckDocdbClusterEncrypted(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "DocumentDB.1")
	/* Description:
	This control checks whether an Amazon DocumentDB cluster is encrypted at rest. The control fails if an Amazon DocumentDB cluster isn't encrypted at rest.
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

	unencryptedClusters := 0

	for _, cluster := range resp.DBClusters {
		log.Printf("└─[*] Checking cluster: %s", aws.ToString(cluster.DBClusterIdentifier))

		if cluster.StorageEncrypted == nil || !*cluster.StorageEncrypted {
			log.Printf("  └─[FAIL] Cluster %s is not encrypted at rest", aws.ToString(cluster.DBClusterIdentifier))
			unencryptedClusters++
		} else {
			log.Printf("  └─[PASS] Cluster %s is encrypted at rest", aws.ToString(cluster.DBClusterIdentifier))
		}
	}

	if unencryptedClusters > 0 {
		log.Printf("└─[FAIL] %d unencrypted DocumentDB clusters found", unencryptedClusters)
		return "FAIL"
	}

	log.Println("└─[PASS] All DocumentDB clusters are encrypted at rest")
	return "PASS"
}
