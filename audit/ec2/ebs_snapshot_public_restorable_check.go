package ec2

import (
	"context"
	"fmt"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Check for publicly restorable EBS snapshots
func CheckEbsSnapshotPublic(client *ec2.Client) {
	// Load compliance data and print the description for EC2.1
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Fatalf("[-] Error loading compliance data: %v", err)
	}
	util.PrintComplianceInfo(compliance, "EC2.1")

	fmt.Println("[*] Fetching EBS snapshots...")
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	}
	resp, err := client.DescribeSnapshots(context.TODO(), input)
	if err != nil {
		log.Fatalf("[-] Failed to describe EBS snapshots: %v", err)
	}

	fmt.Println("    [+] Successfully fetched EBS snapshots")
	for _, snapshot := range resp.Snapshots {
		checkSnapshotPublicAccess(client, *snapshot.SnapshotId)
	}
}

// Check if the snapshot is publicly restorable by using DescribeSnapshotAttribute
func checkSnapshotPublicAccess(client *ec2.Client, snapshotId string) {
	attributeInput := &ec2.DescribeSnapshotAttributeInput{
		Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		SnapshotId: &snapshotId,
	}

	attributeResp, err := client.DescribeSnapshotAttribute(context.TODO(), attributeInput)
	if err != nil {
		log.Fatalf("[-] Failed to describe snapshot attributes for %s: %v", snapshotId, err)
	}

	// Check if the snapshot is publicly restorable
	isPublic := false
	for _, permission := range attributeResp.CreateVolumePermissions {
		if permission.Group == types.PermissionGroupAll {
			isPublic = true
			break
		}
	}

	if isPublic {
		fmt.Printf("    [-] EBS Snapshot %s is publicly restorable\n", snapshotId)
	} else {
		fmt.Printf("    [+] EBS Snapshot %s is not publicly restorable\n", snapshotId)
	}
}
