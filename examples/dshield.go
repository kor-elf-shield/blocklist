package main

import (
	"fmt"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of IP addresses from a service https://dshield.org/
 */

func main() {
	url := "https://www.dshield.org/block.txt"
	extract := parser.NewCIDRTextExtract(0, 2, "\t")
	pars, err := parser.NewText(extract)
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

	/*
		// You can also get a range of IP addresses from this service (from to)
		url := "https://www.dshield.org/block.txt"
		extract := parser.NewIntervalTextExtract(0, 1, "\t")
		pars, err := parser.NewText(extract)
		if err != nil {
			panic(err)
		}
		// limit 0 - no limit
		limit := uint(0)
		config := blocklist.NewConfigWithValidator(limit, &parser.IPRangeValidator{})
		ips, err := blocklist.Get(url, pars, config)
		if err != nil {
			panic(err)
		}
		fmt.Println(ips)
	*/
}
