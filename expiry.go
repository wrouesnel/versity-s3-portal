package main

import (
	"strconv"
	"strings"
	"time"
)

// KeyPolicy is how long keys last: the default for keys made on the Keys page, the
// default for login keys (s3-portal login), and the most anyone but an admin may ask for.
// Admins set it on the admin page; it's kept in the portal's state.
type KeyPolicy struct {
	Default time.Duration `json:"default"`
	Login   time.Duration `json:"login"`
	Max     time.Duration `json:"max"`
}

const day = 24 * time.Hour

// DefaultKeyPolicy is the policy until an admin sets one.
var DefaultKeyPolicy = KeyPolicy{Default: 90 * day, Login: 12 * time.Hour, Max: 365 * day}

// lifetimePresets are the lifetimes a new key's form offers, up to the maximum.
var lifetimePresets = []time.Duration{day, 7 * day, 30 * day, 90 * day, 180 * day, 365 * day}

// LifetimeChoice is one of a key form's lifetimes: Value as parseLifetime reads it.
type LifetimeChoice struct {
	Value, Label string
	Selected     bool
}

// lifetimeChoices are the presets up to the policy's maximum (and the maximum itself),
// with selected chosen, and "never" for admins.
func lifetimeChoices(pol KeyPolicy, selected time.Duration, admin, never bool) []LifetimeChoice {
	var out []LifetimeChoice
	seen := false
	for _, d := range lifetimePresets {
		if d > pol.Max {
			break
		}
		out = append(out, LifetimeChoice{Value: formatLifetime(d), Label: lifetimeLabel(d), Selected: !never && d == selected})
		seen = seen || d == pol.Max
	}
	if !seen {
		out = append(out, LifetimeChoice{Value: formatLifetime(pol.Max), Label: lifetimeLabel(pol.Max) + " (the most)", Selected: !never && pol.Max == selected})
	}
	if admin {
		out = append(out, LifetimeChoice{Value: "never", Label: "Never expires (admins only)", Selected: never})
	}
	return out
}

// parseLifetime reads "12h", "30d", "2w" or "never" (0, true).
func parseLifetime(s string) (time.Duration, bool, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "never" {
		return 0, true, nil
	}
	units := map[byte]time.Duration{'h': time.Hour, 'd': day, 'w': 7 * day}
	if len(s) >= 2 {
		if u, ok := units[s[len(s)-1]]; ok {
			if n, err := strconv.Atoi(s[:len(s)-1]); err == nil && n > 0 {
				return time.Duration(n) * u, false, nil
			}
		}
	}
	return 0, false, userErr("%q isn't a lifetime: give hours, days or weeks (12h, 30d, 2w), or never.", s)
}

// formatLifetime is d as parseLifetime reads it: days if whole, else hours.
func formatLifetime(d time.Duration) string {
	if d%day == 0 {
		return strconv.Itoa(int(d/day)) + "d"
	}
	return strconv.Itoa(int(d.Round(time.Hour)/time.Hour)) + "h"
}

// lifetimeLabel is d for people: "12 hours", "1 day", "90 days", "1 year".
func lifetimeLabel(d time.Duration) string {
	switch {
	case d == 365*day:
		return "1 year"
	case d%day == 0:
		return plural(int64(d/day), "day")
	default:
		return plural(int64(d.Round(time.Hour)/time.Hour), "hour")
	}
}

// expiryLabel is when a key expires, for people: "never expires", "expired", "expires in 11
// hours", "expires in 3 days".
func expiryLabel(expires *time.Time) string {
	if expires == nil {
		return "never expires"
	}
	left := time.Until(*expires)
	switch {
	case left <= 0:
		return "expired"
	case left < time.Hour:
		return "expires in " + plural(int64(left.Minutes())+1, "minute")
	case left < 2*day:
		return "expires in " + plural(int64(left.Hours()+0.5), "hour")
	default:
		return "expires in " + plural(int64(left.Hours()/24+0.5), "day")
	}
}

// expiringSoon is whether a key expires within 7 days, or a tenth of its lifetime for a
// short one, so its owner is warned.
func expiringSoon(k *Key) bool {
	if k.Expires == nil {
		return false
	}
	left := time.Until(*k.Expires)
	life := k.Expires.Sub(k.Created)
	if life < 70*day {
		return left < life/10
	}
	return left < 7*day
}
