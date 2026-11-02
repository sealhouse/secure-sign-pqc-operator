package versions

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadImages(t *testing.T) {
	fsys := fstest.MapFS{"9.9/images.env": {Data: []byte("# comment\n\nTSA_IMAGE=r/tsa@sha256:abc\n")}}
	got, err := LoadImages(fsys, "9.9")
	if err != nil {
		t.Fatal(err)
	}
	if got[ImageTSA] != "r/tsa@sha256:abc" || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestLoadImagesRejects(t *testing.T) {
	for name, body := range map[string]string{
		"tag only":  "TSA_IMAGE=r/tsa:latest\n",
		"no value":  "TSA_IMAGE=\n",
		"no equals": "TSA_IMAGE\n",
		"duplicate": "TSA_IMAGE=r@sha256:a\nTSA_IMAGE=r@sha256:b\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadImages(fstest.MapFS{"1/images.env": {Data: []byte(body)}}, "1"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestOverride(t *testing.T) {
	set := func() Set {
		return Set{
			{Version: "2.0", Images: map[string]string{ImageTSA: "r/tsa@sha256:20"}},
			{Version: "2.1", Images: map[string]string{ImageTSA: "r/tsa@sha256:21"}},
		}
	}
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}

	s := set()
	used, err := s.Override(env(map[string]string{"RELATED_IMAGE_TSA_2_1": "mirror/tsa@sha256:21", "RELATED_IMAGE_TSA_2_2": "x@sha256:1"}))
	if err != nil {
		t.Fatal(err)
	}
	if s[0].Images[ImageTSA] != "r/tsa@sha256:20" || s[1].Images[ImageTSA] != "mirror/tsa@sha256:21" {
		t.Errorf("images %v %v", s[0].Images, s[1].Images)
	}
	if strings.Join(used, ",") != "RELATED_IMAGE_TSA_2_1" {
		t.Errorf("used %v", used)
	}

	for name, ref := range map[string]string{"tag only": "mirror/tsa:2.0", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			s := set()
			if _, err := s.Override(env(map[string]string{"RELATED_IMAGE_TSA_2_0": ref})); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCanMove(t *testing.T) {
	s := Set{{Version: "2.0"}, {Version: "2.1"}, {Version: "2.2"}}
	for _, tc := range []struct {
		from, to string
		ok       bool
	}{
		{"2.0", "2.0", true},
		{"2.0", "2.1", true},
		{"2.1", "2.2", true},
		{"2.0", "2.2", false},
		{"2.1", "2.0", false},
		{"2.2", "3.0", false},
	} {
		if got := s.CanMove(tc.from, tc.to); got != tc.ok {
			t.Errorf("CanMove(%s, %s) = %v, want %v", tc.from, tc.to, got, tc.ok)
		}
	}
	if strings.Join(s.Versions(), ",") != "2.0,2.1,2.2" {
		t.Errorf("Versions %v", s.Versions())
	}
}

func TestProfileImage(t *testing.T) {
	p := &Profile{Version: "2.0", Images: map[string]string{ImageTSA: "x@sha256:1"}, Capabilities: []Capability{CapabilityTSA}}
	if _, err := p.Image("FULCIO_IMAGE"); err == nil {
		t.Error("missing image accepted")
	}
	if !p.Has(CapabilityTSA) {
		t.Error("Has(tsa) false")
	}
}

func TestTransitionRule(t *testing.T) {
	if got := TransitionRule([]string{"2.0"}); got != "self == oldSelf" {
		t.Errorf("one version: %s", got)
	}
}
