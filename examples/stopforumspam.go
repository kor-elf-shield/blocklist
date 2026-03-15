package main

import (
	"fmt"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of IP addresses from a service https://www.stopforumspam.com/downloads
 */

func main() {
	url := "https://www.stopforumspam.com/downloads/listed_ip_1.zip"
	//url := "https://www.stopforumspam.com/downloads/listed_ip_1_ipv6.zip"
	extract := parser.NewDefaultTextExtract(0, " ")
	pars, err := parser.NewText(extract)
	if err != nil {
		panic(err)
	}
	// limit 0 - no limit
	limit := uint(0)
	config := blocklist.NewConfig(limit)
	configZip := blocklist.NewConfigZip(config)
	ips, err := blocklist.GetZip(url, pars, configZip)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)
}
