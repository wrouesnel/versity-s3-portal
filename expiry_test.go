package main

import (
	"testing"
	"time"
)

func TestParseLifetime(t *testing.T) {
	for in, want := range map[string]time.Duration{"12h": 12 * time.Hour, "30d": 30 * day, "2w": 14 * day, " 7D ": 7 * day} {
		if d, never, err := parseLifetime(in); err != nil || never || d != want {
			t.Errorf("%q: %v %v %v", in, d, never, err)
		}
	}
	if _, never, err := parseLifetime("never"); err != nil || !never {
		t.Errorf("never: %v %v", never, err)
	}
	for _, bad := range []string{"", "0d", "-1d", "12", "1y", "1.5d", "d"} {
		if _, _, err := parseLifetime(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
	for d, want := range map[time.Duration]string{12 * time.Hour: "12h", 90 * day: "90d", 36 * time.Hour: "36h"} {
		if got := formatLifetime(d); got != want {
			t.Errorf("format %v: %q", d, got)
		}
	}
	for d, want := range map[time.Duration]string{time.Hour: "1 hour", 12 * time.Hour: "12 hours", day: "1 day", 90 * day: "90 days", 365 * day: "1 year"} {
		if got := lifetimeLabel(d); got != want {
			t.Errorf("label %v: %q", d, got)
		}
	}
}

func TestLifetimeChoices(t *testing.T) {
	pol := KeyPolicy{Default: 30 * day, Login: 12 * time.Hour, Max: 45 * day}
	got := lifetimeChoices(pol, 30*day, false, false)
	var values []string
	selected := ""
	for _, c := range got {
		values = append(values, c.Value)
		if c.Selected {
			selected = c.Value
		}
	}
	// The presets up to the most, then the most itself; no never for people.
	if want := "1d 7d 30d 45d"; joinStr(values) != want || selected != "30d" {
		t.Errorf("choices %v, selected %q", values, selected)
	}
	got = lifetimeChoices(DefaultKeyPolicy, 0, true, true)
	if last := got[len(got)-1]; last.Value != "never" || !last.Selected || got[len(got)-2].Value != "365d" {
		t.Errorf("an admin's choices: %+v", got)
	}
}

func joinStr(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}

func TestExpiryLabels(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	for _, c := range []struct {
		exp  *time.Time
		want string
	}{
		{nil, "never expires"}, {at(-time.Minute), "expired"}, {at(30 * time.Minute), "expires in 30 minutes"},
		{at(9*time.Hour + time.Minute), "expires in 9 hours"}, {at(5*day + time.Hour), "expires in 5 days"},
	} {
		if got := expiryLabel(c.exp); got != c.want {
			t.Errorf("%v: %q, want %q", c.exp, got, c.want)
		}
	}
	// Soon: within 7 days of a long key, within a tenth of a short one's life.
	long := &Key{Created: now.Add(-85 * day), Expires: at(5 * day)}
	login := &Key{Created: now.Add(-11 * time.Hour), Expires: at(time.Hour)}
	fresh := &Key{Created: now.Add(-time.Hour), Expires: at(11 * time.Hour)}
	if !expiringSoon(long) || !expiringSoon(login) || expiringSoon(fresh) || expiringSoon(&Key{}) {
		t.Error("expiring soon")
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{"HXQM-4TRW": "HXQM-4TRW", "hxqm4trw": "HXQM-4TRW", " hxqm 4trw ": "HXQM-4TRW", "HXQM-4TR": "", "HAQM-4TRW": "", "": ""} {
		if got := normalizeCode(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if c := cleanComputer("<script>laptop\n"); c != "scriptlaptop" {
		t.Errorf("computer %q", c)
	}
}
