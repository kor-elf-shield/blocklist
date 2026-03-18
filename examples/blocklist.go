package main

import (
	"fmt"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of IP addresses from a service https://www.blocklist.de/en/export.html
 */

func main() {
	// Getting a list of IP addresses that were entered in the last hour
	// time=seconds
	url := "https://api.blocklist.de/getlast.php?time=3600"
	extract := parser.NewDefaultTextExtract(0, "\t")
	pars, err := parser.NewText(extract)
	if err != nil {
		panic(err)
	}
	// limit 0 - no limit
	limit := uint(0)
	config := blocklist.NewConfig(limit)

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

	/*
		// This second list retrieves all the IP addresses added in the last 48 hours and is usually a
		// very large list (over 10000 entries), so be sure that you have the resources available to use it
		url := "http://lists.blocklist.de/lists/all.txt"
		extract := parser.NewDefaultTextExtract(0, "\t")
		pars, err := parser.NewText(extract)
		if err != nil {
			panic(err)
		}
		// limit 0 - no limit
		limit := uint(0)
		config := blocklist.NewConfig(limit)

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
	*/
}
