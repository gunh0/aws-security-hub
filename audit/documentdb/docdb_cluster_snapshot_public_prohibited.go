package documentdb

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

func CheckDocdbClusterSnapshotPublicProhibited(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}

	util.PrintComplianceInfo(compliance, "DocumentDB.3")
	/* Description:
	This control checks whether an Amazon DocumentDB manual cluster snapshot is public. The control fails if the manual cluster snapshot is public.
	*/

	// Create DocumentDB client
	client := docdb.NewFromConfig(cfg)

	// Describe DocumentDB cluster snapshots
	log.Println("[*] Fetching DocumentDB cluster snapshots...")
	input := &docdb.DescribeDBClusterSnapshotsInput{
		SnapshotType: aws.String("manual"),
	}

	paginator := docdb.NewDescribeDBClusterSnapshotsPaginator(client, input)

	publicSnapshots := 0

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("└─[ERROR] Failed to describe DocumentDB cluster snapshots: %v", err)
			return "NA"
		}

		for _, snapshot := range output.DBClusterSnapshots {
			log.Printf("└─[*] Checking snapshot: %s", aws.ToString(snapshot.DBClusterSnapshotIdentifier))

			// Check if the snapshot is public
			attrInput := &docdb.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: snapshot.DBClusterSnapshotIdentifier,
			}
			attrOutput, err := client.DescribeDBClusterSnapshotAttributes(context.TODO(), attrInput)
			if err != nil {
				log.Printf("  └─[ERROR] Failed to describe snapshot attributes: %v", err)
				continue
			}

			for _, attr := range attrOutput.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
				if aws.ToString(attr.AttributeName) == "restore" {
					for _, value := range attr.AttributeValues {
						if value == "all" {
							log.Printf("  └─[FAIL] Snapshot %s is public", aws.ToString(snapshot.DBClusterSnapshotIdentifier))
							publicSnapshots++
							break
						}
					}
				}
			}

			if publicSnapshots == 0 {
				log.Printf("  └─[PASS] Snapshot %s is not public", aws.ToString(snapshot.DBClusterSnapshotIdentifier))
			}
		}
	}

	if publicSnapshots > 0 {
		log.Printf("└─[FAIL] %d public DocumentDB cluster snapshots found", publicSnapshots)
		return "FAIL"
	}

	if publicSnapshots == 0 {
		log.Println("└─[PASS] No public DocumentDB cluster snapshots found")
		return "PASS"
	}

	return "NA"
}
