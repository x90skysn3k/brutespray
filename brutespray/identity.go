package brutespray

import "strings"

// AttemptIdentity is the scheduler key for lockout-sensitive account attempts.
type AttemptIdentity struct {
	Service string
	Domain  string
	User    string
}

// NewAttemptIdentity normalizes service/domain/user into a stable scheduler key.
func NewAttemptIdentity(service, domain, user string) AttemptIdentity {
	user = strings.TrimSpace(user)
	if embeddedDomain, embeddedUser, ok := strings.Cut(user, `\`); ok {
		domain = embeddedDomain
		user = embeddedUser
	}
	return AttemptIdentity{
		Service: strings.ToLower(strings.TrimSpace(service)),
		Domain:  strings.ToLower(strings.TrimSpace(domain)),
		User:    strings.ToLower(strings.TrimSpace(user)),
	}
}

// Key returns a compact stable identity key.
func (id AttemptIdentity) Key() string {
	return id.Service + "|" + id.Domain + "|" + id.User
}
