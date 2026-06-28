package brutespray

type credentialPair struct {
	User     string
	Password string
}

type credentialOrderOptions struct {
	mode              string
	sprayMode         bool
	useUsernameAsPass bool
	useReversedPass   bool
}

func buildCredentialPairs(users []string, passwords []string, opts credentialOrderOptions) []credentialPair {
	mode := opts.mode
	if mode == "" || mode == "auto" {
		if opts.sprayMode {
			mode = "spray"
		} else {
			mode = "host-major"
		}
	}

	pairs := make([]credentialPair, 0, len(users)*len(passwords))
	appendUserExtras := func(u string) {
		if opts.useUsernameAsPass {
			pairs = append(pairs, credentialPair{User: u, Password: u})
		}
		if opts.useReversedPass {
			reversed := reverseString(u)
			if reversed != u {
				pairs = append(pairs, credentialPair{User: u, Password: reversed})
			}
		}
	}

	switch mode {
	case "spray":
		if opts.useUsernameAsPass {
			for _, u := range users {
				pairs = append(pairs, credentialPair{User: u, Password: u})
			}
		}
		if opts.useReversedPass {
			for _, u := range users {
				reversed := reverseString(u)
				if reversed != u {
					pairs = append(pairs, credentialPair{User: u, Password: reversed})
				}
			}
		}
		for _, p := range passwords {
			for _, u := range users {
				pairs = append(pairs, credentialPair{User: u, Password: p})
			}
		}
	case "pairwise":
		for _, u := range users {
			appendUserExtras(u)
		}
		n := len(users)
		if len(passwords) < n {
			n = len(passwords)
		}
		for i := 0; i < n; i++ {
			pairs = append(pairs, credentialPair{User: users[i], Password: passwords[i]})
		}
	default:
		for _, u := range users {
			appendUserExtras(u)
			for _, p := range passwords {
				pairs = append(pairs, credentialPair{User: u, Password: p})
			}
		}
	}
	return pairs
}
