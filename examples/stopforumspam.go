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

	// Get IPv4 and IPv6 addresses in one list
	ips, err := blocklist.GetZip(url, pars, configZip)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)

	// Get IPv4 and IPv6 addresses in two lists
	ipsV4, ipsV6, err := blocklist.GetZipSeparatedIPs(url, pars, configZip)
	if err != nil {
		panic(err)
	}
	fmt.Println("IPv4")
	fmt.Println(ipsV4)
	fmt.Println("IPv6")
	fmt.Println(ipsV6)
}
