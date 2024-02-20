package ec2

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func CheckEbsSnapshotPublicRestorableCheck(client *ec2.Client) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("└─[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "EC2.1")
	/* Description:
	This control checks whether Amazon Elastic Block Store snapshots are not public. The control fails if Amazon EBS snapshots are restorable by anyone.
	*/

	log.Println("[*] Fetching EBS snapshots...")
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	}
	resp, err := client.DescribeSnapshots(context.TODO(), input)
	if err != nil {
		log.Printf("└─[ERROR] Failed to describe EBS snapshots: %v", err)
		return "NA"
	}

	if len(resp.Snapshots) == 0 {
		log.Println("└─[*] No EBS snapshots found")
		return "PASS"
	}

	publicSnapshots := 0

	for _, snapshot := range resp.Snapshots {
		log.Printf("└─[*] Checking snapshot: %s", *snapshot.SnapshotId)

		attributeInput := &ec2.DescribeSnapshotAttributeInput{
			Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
			SnapshotId: snapshot.SnapshotId,
		}

		attributeResp, err := client.DescribeSnapshotAttribute(context.TODO(), attributeInput)
		if err != nil {
			log.Printf("  └─[ERROR] Failed to describe snapshot attribute: %v", err)
			continue
		}

		for _, permission := range attributeResp.CreateVolumePermissions {
			if permission.Group == "all" {
				log.Printf("  └─[FAIL] Snapshot %s is public", *snapshot.SnapshotId)
				publicSnapshots++
				break
			}
		}

		if publicSnapshots == 0 {
			log.Printf("  └─[PASS] Snapshot %s is not public", *snapshot.SnapshotId)
		}
	}

	if publicSnapshots > 0 {
		log.Printf("└─[FAIL] %d public snapshots found", publicSnapshots)
		return "FAIL"
	}

	log.Println("└─[PASS] No public snapshots found")
	return "PASS"
}
