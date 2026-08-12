package parser

func appendIfNotExcluded(ip string, ips []string, validator IPValidator) ([]string, error) {
	if exclude, listIP, err := validator.IsExcluded(ip); err != nil {
		return ips, err
	} else if exclude {
		if listIP == nil || len(listIP) == 0 {
			return ips, nil
		}
		ips = append(ips, listIP...)
		return ips, nil
	}

	ips = append(ips, ip)
	return ips, nil
}
