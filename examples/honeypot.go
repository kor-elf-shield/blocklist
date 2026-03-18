package main

import (
	"encoding/xml"
	"fmt"
	"strings"

	"git.kor-elf.net/kor-elf-shield/blocklist"
	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

/**
 * An example of how to get a list of IP addresses from a service https://www.projecthoneypot.org/list_of_ips.php
 */

type rssItem struct {
	Title string `xml:"title"`
}

func main() {
	url := "https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1"
	pars, err := parser.NewRss(func(decoder *xml.Decoder, start xml.StartElement) (string, error) {
		if start.Name.Local != "item" {
			return "", nil
		}

		var rssItem rssItem
		if err := decoder.DecodeElement(&rssItem, &start); err != nil {
			return "", fmt.Errorf("decode rss item: %w", err)
		}

		if rssItem.Title == "" {
			return "", nil
		}

		fields := strings.Split(rssItem.Title, "|")
		if len(fields) != 2 {
			return "", nil
		}
		return strings.TrimSpace(fields[0]), nil
	})
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
}
