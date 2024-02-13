// audit/ec2/restricted_common_ports.go

package ec2

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// List of high-risk ports
var highRiskPorts = []int32{20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300}

// Check security group for unrestricted access on high-risk ports
func CheckSecurityGroup(client *ec2.Client) {
	fmt.Println("[*] Fetching EC2 security groups...")
	input := &ec2.DescribeSecurityGroupsInput{}
	resp, err := client.DescribeSecurityGroups(context.TODO(), input)
	if err != nil {
		log.Fatalf("[-] Failed to describe security groups: %v", err)
	}

	fmt.Println("    [+] Successfully fetched security groups")
	for i, sg := range resp.SecurityGroups {
		indicator := "├─"
		if i == len(resp.SecurityGroups)-1 {
			indicator = "└─"
		}
		fmt.Printf("    %s Checking Security Group: %s (%s)\n", indicator, *sg.GroupName, *sg.GroupId)
		checkIngressRules(sg, i == len(resp.SecurityGroups)-1)
	}
}

// Inspect inbound rules of a security group
func checkIngressRules(sg types.SecurityGroup, isLastGroup bool) {
	for i, rule := range sg.IpPermissions {
		if rule.FromPort != nil && rule.ToPort != nil {
			for _, port := range highRiskPorts {
				if port >= *rule.FromPort && port <= *rule.ToPort {
					indicator := "│   ├─"
					if i == len(sg.IpPermissions)-1 {
						indicator = "│   └─"
						if isLastGroup {
							indicator = "    └─"
						}
					}
					checkForUnrestrictedAccess(sg.GroupId, rule, port, indicator)
				}
			}
		}
	}
}

// Check for unrestricted access (0.0.0.0/0 or ::/0) on high-risk ports
func checkForUnrestrictedAccess(groupId *string, rule types.IpPermission, port int32, prefix string) {
	for _, ipRange := range rule.IpRanges {
		if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
			fmt.Printf("    %s [-] Security Group %s allows unrestricted access to port %d from 0.0.0.0/0\n", prefix, *groupId, port)
		}
	}

	for _, ipv6Range := range rule.Ipv6Ranges {
		if ipv6Range.CidrIpv6 != nil && *ipv6Range.CidrIpv6 == "::/0" {
			fmt.Printf("    %s [-] Security Group %s allows unrestricted access to port %d from ::/0\n", prefix, *groupId, port)
		}
	}

	if len(rule.IpRanges) == 0 && len(rule.Ipv6Ranges) == 0 {
		fmt.Printf("    %s [+] Security Group %s has no unrestricted access on port %d\n", prefix, *groupId, port)
	}
}
