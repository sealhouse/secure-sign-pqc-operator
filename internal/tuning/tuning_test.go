package tuning

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaultsAreValid(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
	if got := Defaults().BackoffMax; got != 60*time.Second {
		t.Fatalf("backoff max %s, want 60s", got)
	}
}

func TestEveryFieldHasAnOverride(t *testing.T) {
	// Setting every key to a distinct valid value must change every value,
	// so a field missing from the table would show up here.
	data := map[string]string{
		"backoff_base": "1s", "backoff_max": "2s", "queue_qps": "3", "queue_burst": "4",
		"api_qps": "5", "api_burst": "6", "api_timeout": "7s", "sync_period": "8s",
		"concurrent_reconciles": "9", "degraded_after": "10",
		"lease_duration": "13s", "renew_deadline": "12s", "retry_period": "11s",
		"expiry_warning": "14s",
	}
	if len(data) != len(Keys()) {
		t.Fatalf("test covers %d keys, package has %d", len(data), len(Keys()))
	}
	s, err := WithConfigMap(Defaults(), data)
	if err != nil {
		t.Fatal(err)
	}
	d, v := Defaults().Values(), s.Values()
	for _, k := range Keys() {
		if d[k] == v[k] {
			t.Errorf("%s unchanged by override", k)
		}
	}
}

func TestEnvOverrides(t *testing.T) {
	s, err := FromEnv(env(map[string]string{"PQC_OPERATOR_BACKOFF_MAX": "5s", "PQC_OPERATOR_API_QPS": "50", "PQC_OPERATOR_API_BURST": "80"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.BackoffMax != 5*time.Second || s.APIQPS != 50 || s.APIBurst != 80 {
		t.Fatalf("got %+v", s)
	}
}

func TestEnvInvalidNamesVariable(t *testing.T) {
	_, err := FromEnv(env(map[string]string{"PQC_OPERATOR_BACKOFF_MAX": "soon"}))
	if err == nil || !strings.Contains(err.Error(), "PQC_OPERATOR_BACKOFF_MAX") {
		t.Fatalf("got %v, want error naming PQC_OPERATOR_BACKOFF_MAX", err)
	}
}

func TestConfigMapOverridesEnv(t *testing.T) {
	base, err := FromEnv(env(map[string]string{"PQC_OPERATOR_BACKOFF_MAX": "30s"}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := WithConfigMap(base, map[string]string{"backoff_max": "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if s.BackoffMax != 5*time.Second {
		t.Fatalf("ConfigMap did not take precedence: %s", s.BackoffMax)
	}
}

func TestConfigMapInvalidLeavesBase(t *testing.T) {
	base := Defaults()
	for name, data := range map[string]map[string]string{
		"unparsable":     {"backoff_max": "5s", "api_timeout": "x"},
		"unknown key":    {"backoff_max": "5s", "backof_max": "5s"},
		"base above max": {"backoff_base": "2m"},
		"lease order":    {"renew_deadline": "200s"},
		"burst below":    {"api_burst": "1"},
		"zero":           {"concurrent_reconciles": "0"},
		"negative":       {"sync_period": "-1h"},
		"expiry in sync": {"expiry_warning": "1h"},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := WithConfigMap(base, data)
			if err == nil {
				t.Fatal("accepted invalid ConfigMap")
			}
			if s != base {
				t.Fatal("invalid ConfigMap changed the settings")
			}
		})
	}
}

func TestRestartNeeded(t *testing.T) {
	base := Defaults()
	for data, want := range map[string]string{
		"backoff_base=1ms,backoff_max=1s,queue_qps=5,queue_burst=50,api_timeout=5s,degraded_after=5,expiry_warning=720h": "",
		"concurrent_reconciles=2":              "concurrent_reconciles",
		"api_qps=10,api_burst=10":              "api_qps,api_burst",
		"sync_period=1h,lease_duration=200s":   "sync_period,lease_duration",
		"renew_deadline=100s,retry_period=20s": "renew_deadline,retry_period",
	} {
		cm := map[string]string{}
		for kv := range strings.SplitSeq(data, ",") {
			k, v, _ := strings.Cut(kv, "=")
			cm[k] = v
		}
		s, err := WithConfigMap(base, cm)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		if got := strings.Join(RestartNeeded(base, s), ","); got != want {
			t.Errorf("%s: restart for %q, want %q", data, got, want)
		}
	}
}
