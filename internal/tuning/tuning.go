// Package tuning holds the operator's retry, backoff, client and leader
// election settings.
package tuning

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ConfigMapName is the ConfigMap read from the operator's namespace.
const ConfigMapName = "securesign-pqc-operator-config"

// EnvPrefix prefixes every environment variable name.
const EnvPrefix = "PQC_OPERATOR_"

// Settings are the effective tuning values.
type Settings struct {
	// BackoffBase and BackoffMax bound the per-object exponential requeue.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// QueueQPS and QueueBurst bound the overall requeue rate.
	QueueQPS   float64
	QueueBurst int
	// APIQPS, APIBurst and APITimeout configure the API client.
	APIQPS     float64
	APIBurst   int
	APITimeout time.Duration
	// SyncPeriod is the informer resync period.
	SyncPeriod time.Duration
	// ConcurrentReconciles is the number of SecureSignPQC workers.
	ConcurrentReconciles int
	// DegradedAfter is the number of consecutive failures before Degraded.
	DegradedAfter int
	// Leader election timings.
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration
	// ExpiryWarning is how long before a certificate in use expires that
	// the operator reports it.
	ExpiryWarning time.Duration
}

// Defaults returns the built-in settings.
func Defaults() Settings {
	return Settings{
		BackoffBase:          5 * time.Millisecond,
		BackoffMax:           60 * time.Second,
		QueueQPS:             10,
		QueueBurst:           100,
		APIQPS:               20,
		APIBurst:             30,
		APITimeout:           30 * time.Second,
		SyncPeriod:           10 * time.Hour,
		ConcurrentReconciles: 1,
		DegradedAfter:        3,
		LeaseDuration:        137 * time.Second,
		RenewDeadline:        107 * time.Second,
		RetryPeriod:          26 * time.Second,
		ExpiryWarning:        90 * 24 * time.Hour,
	}
}

type kind int

const (
	kindDuration kind = iota
	kindFloat
	kindInt
)

type field struct {
	name string
	kind kind
	// live settings take effect while the operator runs; the others are
	// fixed when its manager is built.
	live bool
	ptr  func(*Settings) any
}

// fields lists every setting by its ConfigMap key. api_qps and api_burst
// size a rate limiter in each API client, built with the client.
var fields = []field{
	{"backoff_base", kindDuration, true, func(s *Settings) any { return &s.BackoffBase }},
	{"backoff_max", kindDuration, true, func(s *Settings) any { return &s.BackoffMax }},
	{"queue_qps", kindFloat, true, func(s *Settings) any { return &s.QueueQPS }},
	{"queue_burst", kindInt, true, func(s *Settings) any { return &s.QueueBurst }},
	{"api_qps", kindFloat, false, func(s *Settings) any { return &s.APIQPS }},
	{"api_burst", kindInt, false, func(s *Settings) any { return &s.APIBurst }},
	{"api_timeout", kindDuration, true, func(s *Settings) any { return &s.APITimeout }},
	{"sync_period", kindDuration, false, func(s *Settings) any { return &s.SyncPeriod }},
	{"concurrent_reconciles", kindInt, false, func(s *Settings) any { return &s.ConcurrentReconciles }},
	{"degraded_after", kindInt, true, func(s *Settings) any { return &s.DegradedAfter }},
	{"lease_duration", kindDuration, false, func(s *Settings) any { return &s.LeaseDuration }},
	{"renew_deadline", kindDuration, false, func(s *Settings) any { return &s.RenewDeadline }},
	{"retry_period", kindDuration, false, func(s *Settings) any { return &s.RetryPeriod }},
	{"expiry_warning", kindDuration, true, func(s *Settings) any { return &s.ExpiryWarning }},
}

// EnvName returns the environment variable for ConfigMap key name.
func EnvName(name string) string { return EnvPrefix + strings.ToUpper(name) }

// Keys returns every ConfigMap key in order.
func Keys() []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.name
	}
	return out
}

func (f field) set(s *Settings, raw, source string) error {
	raw = strings.TrimSpace(raw)
	switch f.kind {
	case kindDuration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("%s: %q is not a duration", source, raw)
		}
		*f.ptr(s).(*time.Duration) = d
	case kindFloat:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("%s: %q is not a number", source, raw)
		}
		*f.ptr(s).(*float64) = v
	case kindInt:
		v, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%s: %q is not an integer", source, raw)
		}
		*f.ptr(s).(*int) = v
	}
	return nil
}

// Validate checks every setting and the relations between them.
func (s Settings) Validate() error {
	var errs []error
	pos := func(name string, ok bool) {
		if !ok {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	pos("backoff_base", s.BackoffBase > 0)
	pos("backoff_max", s.BackoffMax > 0)
	pos("queue_qps", s.QueueQPS > 0)
	pos("queue_burst", s.QueueBurst > 0)
	pos("api_qps", s.APIQPS > 0)
	pos("api_burst", s.APIBurst > 0)
	pos("api_timeout", s.APITimeout > 0)
	pos("sync_period", s.SyncPeriod > 0)
	pos("concurrent_reconciles", s.ConcurrentReconciles > 0)
	pos("degraded_after", s.DegradedAfter > 0)
	pos("lease_duration", s.LeaseDuration > 0)
	pos("renew_deadline", s.RenewDeadline > 0)
	pos("retry_period", s.RetryPeriod > 0)
	pos("expiry_warning", s.ExpiryWarning > 0)
	if s.BackoffBase > s.BackoffMax {
		errs = append(errs, errors.New("backoff_base must not exceed backoff_max"))
	}
	if s.RetryPeriod >= s.RenewDeadline || s.RenewDeadline >= s.LeaseDuration {
		errs = append(errs, errors.New("retry_period < renew_deadline < lease_duration must hold"))
	}
	// Expiry is only checked on a reconcile, at least once per sync_period.
	if s.ExpiryWarning <= s.SyncPeriod {
		errs = append(errs, errors.New("expiry_warning must exceed sync_period"))
	}
	if float64(s.APIBurst) < s.APIQPS {
		errs = append(errs, errors.New("api_burst must be at least api_qps"))
	}
	if float64(s.QueueBurst) < s.QueueQPS {
		errs = append(errs, errors.New("queue_burst must be at least queue_qps"))
	}
	return errors.Join(errs...)
}

// FromEnv applies environment overrides to the defaults.
func FromEnv(lookup func(string) (string, bool)) (Settings, error) {
	s := Defaults()
	var errs []error
	for _, f := range fields {
		if raw, ok := lookup(EnvName(f.name)); ok {
			if err := f.set(&s, raw, EnvName(f.name)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Settings{}, err
	}
	if err := s.Validate(); err != nil {
		return Settings{}, fmt.Errorf("environment: %w", err)
	}
	return s, nil
}

// WithConfigMap applies ConfigMap data on top of base.
func WithConfigMap(base Settings, data map[string]string) (Settings, error) {
	s := base
	var errs []error
	known := map[string]field{}
	for _, f := range fields {
		known[f.name] = f
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		f, ok := known[k]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unknown key", k))
			continue
		}
		if err := f.set(&s, data[k], k); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return base, err
	}
	if err := s.Validate(); err != nil {
		return base, err
	}
	return s, nil
}

// Values returns each setting as a number for the pqc_operator_config
// metric.
func (s Settings) Values() map[string]float64 {
	out := map[string]float64{}
	for _, f := range fields {
		switch v := f.ptr(&s).(type) {
		case *time.Duration:
			out[f.name] = v.Seconds()
		case *float64:
			out[f.name] = *v
		case *int:
			out[f.name] = float64(*v)
		}
	}
	return out
}

// RestartNeeded returns the ConfigMap keys of the settings that differ
// between a and b and cannot change while the operator runs.
func RestartNeeded(a, b Settings) []string {
	va, vb := a.Values(), b.Values()
	var keys []string
	for _, f := range fields {
		if !f.live && va[f.name] != vb[f.name] {
			keys = append(keys, f.name)
		}
	}
	return keys
}

// Live holds the running settings, which a valid ConfigMap change replaces.
type Live struct {
	p atomic.Pointer[Settings]
}

// NewLive returns a Live holding s.
func NewLive(s Settings) *Live {
	l := &Live{}
	l.Store(s)
	return l
}

// Load returns the current settings.
func (l *Live) Load() Settings { return *l.p.Load() }

// Store replaces the settings.
func (l *Live) Store(s Settings) { l.p.Store(&s) }
