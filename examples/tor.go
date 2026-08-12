package main

import (
	"fmt"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of IP addresses from a service https://check.torproject.org/torbulkexitlist
 */

func main() {
	url := "https://check.torproject.org/torbulkexitlist"
	extract := parser.NewDefaultTextExtract(0, " ")
	pars, err := parser.NewText(extract)
	if err != nil {
		panic(err)
	}
	// limit 0 - no limit
	limit := uint(0)
	config := blocklist.NewConfig(limit)

	// If you need to exclude an IP address or subnet
	//excludeIPs := []string{
	//	"172.18.0.2",
	//	//"172.18.0.0/24",
	//	//"172.18.0.0-172.18.0.255",
	//}
	//exclusionChecker, err := parser.NewExclusionChecker(excludeIPs)
	//if err != nil {
	//	panic(err)
	//}
	//config := blocklist.NewConfigWithExclusionChecker(limit, exclusionChecker)

	// Get IPv4 and IPv6 addresses in one list
	ips, err := blocklist.Get(url, pars, config)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)

	// Get IPv4 and IPv6 addresses in two lists
	ipsV4, ipsV6, err := blocklist.GetSeparatedIPs(url, pars, config)
	if err != nil {
		panic(err)
	}
	fmt.Println("IPv4")
	fmt.Println(ipsV4)
	fmt.Println("IPv6")
	fmt.Println(ipsV6)
}
