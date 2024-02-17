package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// Compliance structure to match the JSON structure
type Compliance struct {
	Requirements []struct {
		Id          string `json:"Id"`
		Description string `json:"Description"`
	} `json:"Requirements"`
}

// Load compliance data from the JSON file
func LoadComplianceData(filePath string) (*Compliance, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open compliance file: %v", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read compliance file: %v", err)
	}

	var compliance Compliance
	err = json.Unmarshal(bytes, &compliance)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal compliance data: %v", err)
	}

	return &compliance, nil
}

// Print the specific compliance information
func PrintComplianceInfo(compliance *Compliance, id string) {
	for _, requirement := range compliance.Requirements {
		if requirement.Id == id {
			log.Println(strings.Repeat("-", 100))
			log.Printf("[%s] %s\n", requirement.Id, requirement.Description)
			log.Println(strings.Repeat("-", 100))
			return
		}
	}
	log.Printf("[ERROR] Compliance requirement with ID %s not found.\n", id)
}
