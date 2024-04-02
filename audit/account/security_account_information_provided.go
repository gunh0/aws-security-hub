// audit/account/security_account_information_provided.go
package account

import (
	"context"
	"log"

	"aws-security-hub/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
)

func CheckSecurityAccountInformationProvided(cfg aws.Config) string {
	compliance, err := util.LoadComplianceData("compliance/aws_security_hub.json")
	if err != nil {
		log.Printf("[ERROR] Error loading compliance data: %v", err)
		return "NA"
	}
	util.PrintComplianceInfo(compliance, "Account.1")
	/* Description:
	This control checks if an Amazon Web Services (AWS) account has security contact information. The control fails if security contact information is not provided for the account.
	*/

	// Create Account client
	client := account.NewFromConfig(cfg)

	// Get alternate contacts for security
	input := &account.GetAlternateContactInput{
		AlternateContactType: "SECURITY",
	}

	contact, err := client.GetAlternateContact(context.TODO(), input)
	if err != nil {
		log.Printf("[ERROR] Failed to get security contact information: %v", err)
		return "FAIL"
	}

	if contact.AlternateContact == nil {
		log.Println("[FAIL] No security contact information is configured")
		return "FAIL"
	}

	// Check if all required fields are populated
	hasAllFields := true
	contactInfo := contact.AlternateContact

	if contactInfo.Name == nil || *contactInfo.Name == "" {
		log.Println("  └─[FAIL] Security contact name is not configured")
		hasAllFields = false
	} else {
		log.Printf("  └─[PASS] Security contact name: %s", *contactInfo.Name)
	}

	if contactInfo.EmailAddress == nil || *contactInfo.EmailAddress == "" {
		log.Println("  └─[FAIL] Security contact email is not configured")
		hasAllFields = false
	} else {
		log.Printf("  └─[PASS] Security contact email: %s", *contactInfo.EmailAddress)
	}

	if contactInfo.PhoneNumber == nil || *contactInfo.PhoneNumber == "" {
		log.Println("  └─[FAIL] Security contact phone number is not configured")
		hasAllFields = false
	} else {
		log.Printf("  └─[PASS] Security contact phone number: %s", *contactInfo.PhoneNumber)
	}

	if contactInfo.Title == nil || *contactInfo.Title == "" {
		log.Println("  └─[FAIL] Security contact title is not configured")
		hasAllFields = false
	} else {
		log.Printf("  └─[PASS] Security contact title: %s", *contactInfo.Title)
	}

	if hasAllFields {
		log.Println("[PASS] Security contact information is properly configured")
		return "PASS"
	}

	log.Println("[FAIL] Security contact information is incomplete")
	return "FAIL"
}
