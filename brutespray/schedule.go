package brutespray

import "iter"

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

// credentialPairs traverses the selected order without materializing the
// Cartesian product. Breaking the range stops generation immediately.
func credentialPairs(users []string, passwords []string, opts credentialOrderOptions) iter.Seq[credentialPair] {
	return func(yield func(credentialPair) bool) {
		mode := opts.mode
		if mode == "" || mode == "auto" {
			if opts.sprayMode {
				mode = "spray"
			} else {
				mode = "host-major"
			}
		}
		yieldExtras := func(u string) bool {
			if opts.useUsernameAsPass && !yield(credentialPair{User: u, Password: u}) {
				return false
			}
			if opts.useReversedPass {
				reversed := reverseString(u)
				if reversed != u && !yield(credentialPair{User: u, Password: reversed}) {
					return false
				}
			}
			return true
		}

		switch mode {
		case "spray":
			if opts.useUsernameAsPass {
				for _, u := range users {
					if !yield(credentialPair{User: u, Password: u}) {
						return
					}
				}
			}
			if opts.useReversedPass {
				for _, u := range users {
					reversed := reverseString(u)
					if reversed != u && !yield(credentialPair{User: u, Password: reversed}) {
						return
					}
				}
			}
			for _, p := range passwords {
				for _, u := range users {
					if !yield(credentialPair{User: u, Password: p}) {
						return
					}
				}
			}
		case "pairwise":
			for _, u := range users {
				if !yieldExtras(u) {
					return
				}
			}
			for i := range min(len(users), len(passwords)) {
				if !yield(credentialPair{User: users[i], Password: passwords[i]}) {
					return
				}
			}
		default:
			for _, u := range users {
				if !yieldExtras(u) {
					return
				}
				for _, p := range passwords {
					if !yield(credentialPair{User: u, Password: p}) {
						return
					}
				}
			}
		}
	}
}
