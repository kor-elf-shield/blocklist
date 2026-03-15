package main

import (
	"encoding/json"
	"fmt"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of bad IP addresses from the service https://www.spamhaus.org/blocklists/do-not-route-or-peer/
 */

type lineJson struct {
	IP string `json:"cidr"`
}

func main() {
	url := "https://www.spamhaus.org/drop/drop_v4.json"
	//url := "https://www.spamhaus.org/drop/drop_v6.json"
	pars, err := parser.NewJsonLines(func(item json.RawMessage) (string, error) {
		var line lineJson
		if err := json.Unmarshal(item, &line); err != nil {
			return "", fmt.Errorf("unmarshal json item: %w", err)
		}
		return line.IP, nil
	})
	if err != nil {
		panic(err)
	}
	// limit 0 - no limit
	limit := uint(0)
	config := blocklist.NewConfig(limit)
	ips, err := blocklist.Get(url, pars, config)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)
}
