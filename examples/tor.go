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
	ips, err := blocklist.Get(url, pars, config)
	if err != nil {
		panic(err)
	}
	fmt.Println(ips)
}
