package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions/supported"
)

const defaultBase = "config/manifests/bases/secure-sign-pqc-operator.clusterserviceversion.yaml"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bundle:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		pkg      = flag.String("package", "secure-sign-pqc-operator", "OLM package name")
		ver      = flag.String("version", "", "bundle semantic version")
		replaces = flag.String("replaces", "", "CSV name this bundle replaces")
		channels = flag.String("channels", "alpha", "comma-separated channels; the first is the default")
		image    = flag.String("image", "", "digest-pinned operator image")
		base     = flag.String("base", defaultBase, "CSV base")
		samples  = flag.String("samples", "config/samples/pqc_v1alpha1_securesignpqc.yaml", "comma-separated sample CRs")
		out      = flag.String("out", "", "output directory, absent or empty")
	)
	flag.Parse()
	if *ver == "" || *image == "" || *out == "" {
		return fmt.Errorf("-version, -image and -out are required")
	}

	manifests, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	baseCSV, err := os.ReadFile(*base)
	if err != nil {
		return err
	}
	var sampleData [][]byte
	for path := range strings.SplitSeq(*samples, ",") {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sampleData = append(sampleData, data)
	}
	profiles, err := supported.Load()
	if err != nil {
		return err
	}

	b, err := Generate(Options{
		Package:       *pkg,
		Version:       *ver,
		Replaces:      *replaces,
		Channels:      strings.Split(*channels, ","),
		OperatorImage: *image,
		Base:          baseCSV,
		Manifests:     manifests,
		Samples:       sampleData,
		Profiles:      profiles,
	})
	if err != nil {
		return err
	}
	if err := b.Write(*out); err != nil {
		return err
	}
	if err := Validate(*out); err != nil {
		return err
	}
	fmt.Println(b.CSVName)
	return nil
}
