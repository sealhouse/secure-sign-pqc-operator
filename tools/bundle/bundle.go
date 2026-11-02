// Command bundle writes the operator's OLM registry+v1 bundle, generated from the
// kustomize build of config/default, the hand-written CSV base in
// config/manifests/bases and the supported version profiles.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/operator-framework/api/pkg/lib/version"
	"github.com/operator-framework/api/pkg/manifests"
	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/operator-framework/api/pkg/validation"
	valerrors "github.com/operator-framework/api/pkg/validation/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/sealhouse/secure-sign-pqc-operator/internal/versions"
)

// Media type and annotation keys of a registry+v1 bundle.
const (
	annotationMediaType      = "operators.operatorframework.io.bundle.mediatype.v1"
	annotationManifests      = "operators.operatorframework.io.bundle.manifests.v1"
	annotationMetadata       = "operators.operatorframework.io.bundle.metadata.v1"
	annotationPackage        = "operators.operatorframework.io.bundle.package.v1"
	annotationChannels       = "operators.operatorframework.io.bundle.channels.v1"
	annotationDefaultChannel = "operators.operatorframework.io.bundle.channel.default.v1"
	mediaTypeRegistryV1      = "registry+v1"
)

// managerContainer is the name of the operator's container in config/manager.
const managerContainer = "manager"

// Options are the inputs of Generate.
type Options struct {
	// Package is the OLM package name; the CSV is named <Package>.v<Version>.
	Package string
	// Version is the bundle's semantic version.
	Version string
	// Replaces is the CSV name this bundle replaces, or empty for the first.
	Replaces string
	// Channels lists the channels the bundle is published to; the first is
	// the default.
	Channels []string
	// OperatorImage is the digest-pinned operator image.
	OperatorImage string
	// Base is the hand-written CSV.
	Base []byte
	// Manifests is the kustomize build of config/default.
	Manifests []byte
	// Samples are example custom resources for the alm-examples annotation.
	Samples [][]byte
	// Profiles are the product versions the operator image supports; their
	// operand images become related images.
	Profiles versions.Set
}

// Bundle is a generated bundle: file contents keyed by their path relative
// to the bundle root.
type Bundle struct {
	Files map[string][]byte
	// CSVName is the generated ClusterServiceVersion's name.
	CSVName string
}

// Generate builds the bundle described by o.
func Generate(o Options) (*Bundle, error) {
	if o.Package == "" || len(o.Channels) == 0 {
		return nil, errors.New("package and at least one channel are required")
	}
	if !strings.Contains(o.OperatorImage, "@sha256:") {
		return nil, fmt.Errorf("operator image %q is not pinned by digest", o.OperatorImage)
	}
	v, err := semver.Parse(o.Version)
	if err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if len(v.Build) > 0 {
		// OLM orders bundles by semver precedence, which ignores build
		// metadata, so two builds would compare equal.
		return nil, fmt.Errorf("version %s has build metadata", o.Version)
	}

	var csv operatorsv1alpha1.ClusterServiceVersion
	if err := yaml.UnmarshalStrict(o.Base, &csv); err != nil {
		return nil, fmt.Errorf("CSV base: %w", err)
	}
	objs, err := decodeAll(o.Manifests)
	if err != nil {
		return nil, err
	}
	in, err := sortObjects(objs)
	if err != nil {
		return nil, err
	}

	csv.Name = fmt.Sprintf("%s.v%s", o.Package, v)
	csv.Spec.Version = version.OperatorVersion{Version: v}
	csv.Spec.Replaces = o.Replaces

	deployment, err := installDeployment(in.deployment, o.OperatorImage, o.Profiles)
	if err != nil {
		return nil, err
	}
	perms, clusterPerms, err := in.permissions()
	if err != nil {
		return nil, err
	}
	csv.Spec.InstallStrategy = operatorsv1alpha1.NamedInstallStrategy{
		StrategyName: operatorsv1alpha1.InstallStrategyNameDeployment,
		StrategySpec: operatorsv1alpha1.StrategyDetailsDeployment{
			DeploymentSpecs:    []operatorsv1alpha1.StrategyDeploymentSpec{deployment},
			Permissions:        perms,
			ClusterPermissions: clusterPerms,
		},
	}
	if err := ownCRDs(&csv, in.crds); err != nil {
		return nil, err
	}
	csv.Spec.RelatedImages = relatedImages(o.OperatorImage, o.Profiles)

	if csv.Annotations == nil {
		csv.Annotations = map[string]string{}
	}
	csv.Annotations["containerImage"] = o.OperatorImage
	examples, err := almExamples(o.Samples)
	if err != nil {
		return nil, err
	}
	csv.Annotations["alm-examples"] = examples

	b := &Bundle{Files: map[string][]byte{}, CSVName: csv.Name}
	csvYAML, err := marshalObject(&csv)
	if err != nil {
		return nil, err
	}
	b.Files[filepath.Join("manifests", o.Package+".clusterserviceversion.yaml")] = csvYAML
	for _, u := range in.manifests {
		data, err := marshalObject(u)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("%s_%s.yaml", u.GetName(), strings.ToLower(u.GetKind()))
		b.Files[filepath.Join("manifests", name)] = data
	}

	annotations := map[string]string{
		annotationMediaType:      mediaTypeRegistryV1,
		annotationManifests:      "manifests/",
		annotationMetadata:       "metadata/",
		annotationPackage:        o.Package,
		annotationChannels:       strings.Join(o.Channels, ","),
		annotationDefaultChannel: o.Channels[0],
	}
	meta, err := yaml.Marshal(map[string]any{"annotations": annotations})
	if err != nil {
		return nil, err
	}
	b.Files[filepath.Join("metadata", "annotations.yaml")] = meta
	b.Files["bundle.Dockerfile"] = dockerfile(annotations)
	return b, nil
}

// Write writes the bundle under dir, which must not exist or be empty.
func (b *Bundle) Write(dir string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	}
	for _, name := range slices.Sorted(maps.Keys(b.Files)) {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, b.Files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Validate loads the bundle in dir the way OLM does and runs the
// operator-framework validators that operator-sdk bundle validate runs, plus
// the good-practices and capabilities checks.
func Validate(dir string) error {
	bundle, err := manifests.GetBundleFromDir(dir)
	if err != nil {
		return fmt.Errorf("load bundle: %w", err)
	}
	validators := append(slices.Clone(validation.DefaultBundleValidators),
		validation.GoodPracticesValidator, validation.StandardCapabilitiesValidator)
	var problems []string
	for _, result := range validators.Validate(bundle) {
		for _, e := range result.Errors {
			problems = append(problems, describe(e))
		}
		for _, w := range result.Warnings {
			if !accepted(w) {
				problems = append(problems, describe(w))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("bundle %s is invalid:\n  %s", bundle.Name, strings.Join(problems, "\n  "))
	}
	return nil
}

// acceptedWarnings are validator warnings the bundle is known to raise, each
// with the reason it stands.
var acceptedWarnings = []string{
	// The channels are alpha (every merge) and tech-preview (releases), the
	// names the existing RHTAS operator uses, rather than OLM's recommended
	// candidate/fast/stable.
	"are not following the recommended naming convention",
}

func accepted(w valerrors.Error) bool {
	return slices.ContainsFunc(acceptedWarnings, func(s string) bool { return strings.Contains(w.Error(), s) })
}

func describe(e valerrors.Error) string {
	return fmt.Sprintf("%s: %s", e.Level, e.Error())
}

// objects sorts the kustomize build into what the bundle does with it.
type objects struct {
	deployment   *appsv1.Deployment
	crds         []*unstructured.Unstructured
	roles        map[string]*rbacv1.Role
	clusterRoles map[string]*rbacv1.ClusterRole
	bindings     []*rbacv1.RoleBinding
	clusterBinds []*rbacv1.ClusterRoleBinding
	// serviceAccounts are the build's accounts, the Deployment's first.
	// OLM creates them from the CSV permissions.
	serviceAccounts []string
	// manifests are shipped in the bundle as they are.
	manifests []*unstructured.Unstructured
}

func sortObjects(objs []*unstructured.Unstructured) (*objects, error) {
	in := &objects{roles: map[string]*rbacv1.Role{}, clusterRoles: map[string]*rbacv1.ClusterRole{}}
	var serviceAccounts []string
	for _, u := range objs {
		switch u.GroupVersionKind().GroupKind().String() {
		case "Namespace":
			// OLM installs into the namespace the OperatorGroup is in.
		case "ServiceAccount":
			serviceAccounts = append(serviceAccounts, u.GetName())
		case "Deployment.apps":
			if in.deployment != nil {
				return nil, fmt.Errorf("more than one Deployment: %s and %s", in.deployment.Name, u.GetName())
			}
			in.deployment = &appsv1.Deployment{}
			if err := fromUnstructured(u, in.deployment); err != nil {
				return nil, err
			}
		case "CustomResourceDefinition.apiextensions.k8s.io":
			in.crds = append(in.crds, u)
			in.manifests = append(in.manifests, stripNamespace(u))
		case "Service":
			in.manifests = append(in.manifests, stripNamespace(u))
		case "Role.rbac.authorization.k8s.io":
			var r rbacv1.Role
			if err := fromUnstructured(u, &r); err != nil {
				return nil, err
			}
			in.roles[r.Name] = &r
		case "ClusterRole.rbac.authorization.k8s.io":
			var r rbacv1.ClusterRole
			if err := fromUnstructured(u, &r); err != nil {
				return nil, err
			}
			in.clusterRoles[r.Name] = &r
		case "RoleBinding.rbac.authorization.k8s.io":
			var b rbacv1.RoleBinding
			if err := fromUnstructured(u, &b); err != nil {
				return nil, err
			}
			in.bindings = append(in.bindings, &b)
		case "ClusterRoleBinding.rbac.authorization.k8s.io":
			var b rbacv1.ClusterRoleBinding
			if err := fromUnstructured(u, &b); err != nil {
				return nil, err
			}
			in.clusterBinds = append(in.clusterBinds, &b)
		default:
			return nil, fmt.Errorf("%s %s has no place in the bundle", u.GetKind(), u.GetName())
		}
	}
	if in.deployment == nil {
		return nil, errors.New("the build has no Deployment")
	}
	sa := in.deployment.Spec.Template.Spec.ServiceAccountName
	if !slices.Contains(serviceAccounts, sa) {
		return nil, fmt.Errorf("the build lacks the Deployment's service account %q, has %v", sa, serviceAccounts)
	}
	in.serviceAccounts = append([]string{sa}, slices.DeleteFunc(slices.Sorted(slices.Values(serviceAccounts)),
		func(name string) bool { return name == sa })...)
	return in, nil
}

// permissions resolves every binding into CSV permissions for the service
// account it binds. A ClusterRole not bound to the operator's account is
// also shipped, for admins to bind.
func (in *objects) permissions() (perms, clusterPerms []operatorsv1alpha1.StrategyDeploymentPermissions, err error) {
	operator := in.serviceAccounts[0]
	bound := map[string]bool{}
	subject := func(subjects []rbacv1.Subject, binding string) (string, error) {
		if len(subjects) != 1 || subjects[0].Kind != rbacv1.ServiceAccountKind || !slices.Contains(in.serviceAccounts, subjects[0].Name) {
			return "", fmt.Errorf("binding %s must have a single subject, one of the ServiceAccounts %v", binding, in.serviceAccounts)
		}
		return subjects[0].Name, nil
	}
	nsRules := map[string][]rbacv1.PolicyRule{}
	clusterRules := map[string][]rbacv1.PolicyRule{}
	for _, b := range in.bindings {
		sa, err := subject(b.Subjects, b.Name)
		if err != nil {
			return nil, nil, err
		}
		switch b.RoleRef.Kind {
		case "Role":
			r, ok := in.roles[b.RoleRef.Name]
			if !ok {
				return nil, nil, fmt.Errorf("binding %s names missing Role %s", b.Name, b.RoleRef.Name)
			}
			nsRules[sa] = append(nsRules[sa], r.Rules...)
			delete(in.roles, r.Name)
		case "ClusterRole":
			r, ok := in.clusterRoles[b.RoleRef.Name]
			if !ok {
				return nil, nil, fmt.Errorf("binding %s names missing ClusterRole %s", b.Name, b.RoleRef.Name)
			}
			nsRules[sa] = append(nsRules[sa], r.Rules...)
			bound[r.Name] = bound[r.Name] || sa == operator
		}
	}
	for _, b := range in.clusterBinds {
		sa, err := subject(b.Subjects, b.Name)
		if err != nil {
			return nil, nil, err
		}
		r, ok := in.clusterRoles[b.RoleRef.Name]
		if !ok {
			return nil, nil, fmt.Errorf("binding %s names missing ClusterRole %s", b.Name, b.RoleRef.Name)
		}
		clusterRules[sa] = append(clusterRules[sa], r.Rules...)
		bound[r.Name] = bound[r.Name] || sa == operator
	}
	if len(in.roles) > 0 {
		return nil, nil, fmt.Errorf("roles bound to nobody: %v", slices.Sorted(maps.Keys(in.roles)))
	}
	for _, name := range slices.Sorted(maps.Keys(in.clusterRoles)) {
		if bound[name] {
			continue
		}
		u, err := clusterRoleObject(in.clusterRoles[name])
		if err != nil {
			return nil, nil, err
		}
		in.manifests = append(in.manifests, u)
	}
	for _, sa := range in.serviceAccounts {
		if len(nsRules[sa]) == 0 && len(clusterRules[sa]) == 0 {
			return nil, nil, fmt.Errorf("service account %s is bound to nothing", sa)
		}
		if len(nsRules[sa]) > 0 {
			perms = append(perms, operatorsv1alpha1.StrategyDeploymentPermissions{ServiceAccountName: sa, Rules: nsRules[sa]})
		}
		if len(clusterRules[sa]) > 0 {
			clusterPerms = append(clusterPerms, operatorsv1alpha1.StrategyDeploymentPermissions{ServiceAccountName: sa, Rules: clusterRules[sa]})
		}
	}
	return perms, clusterPerms, nil
}

// installDeployment is the operator Deployment as a CSV deployment spec, with
// the manager container running image.
func installDeployment(
	d *appsv1.Deployment, image string, profiles versions.Set,
) (operatorsv1alpha1.StrategyDeploymentSpec, error) {
	spec := *d.Spec.DeepCopy()
	i := slices.IndexFunc(spec.Template.Spec.Containers, func(c corev1.Container) bool { return c.Name == managerContainer })
	if i < 0 {
		return operatorsv1alpha1.StrategyDeploymentSpec{}, fmt.Errorf("deployment %s has no %s container", d.Name, managerContainer)
	}
	manager := &spec.Template.Spec.Containers[i]
	manager.Image = image
	// The operator deploys these over its embedded pins, so a pipeline that
	// rewrites the CSV's image references rewrites what it deploys.
	for _, p := range profiles {
		for _, key := range slices.Sorted(maps.Keys(p.Images)) {
			name := versions.RelatedImageEnv(key, p.Version)
			if slices.ContainsFunc(manager.Env, func(e corev1.EnvVar) bool { return e.Name == name }) {
				return operatorsv1alpha1.StrategyDeploymentSpec{}, fmt.Errorf("the %s container already sets %s", managerContainer, name)
			}
			manager.Env = append(manager.Env, corev1.EnvVar{Name: name, Value: p.Images[key]})
		}
	}
	return operatorsv1alpha1.StrategyDeploymentSpec{Name: d.Name, Spec: spec, Label: d.Labels}, nil
}

// ownCRDs fills in the CSV's owned CRDs: one entry per served version of each
// CRD in the build, with the display name and description the base gives it.
func ownCRDs(csv *operatorsv1alpha1.ClusterServiceVersion, crds []*unstructured.Unstructured) error {
	described := map[string]operatorsv1alpha1.CRDDescription{}
	for _, d := range csv.Spec.CustomResourceDefinitions.Owned {
		described[d.Name+"/"+d.Version] = d
	}
	var owned []operatorsv1alpha1.CRDDescription
	for _, crd := range crds {
		kind, _, _ := unstructured.NestedString(crd.Object, "spec", "names", "kind")
		vers, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
		for _, raw := range vers {
			v, _ := raw.(map[string]any)
			if served, _ := v["served"].(bool); !served {
				continue
			}
			name, _ := v["name"].(string)
			key := crd.GetName() + "/" + name
			d, ok := described[key]
			if !ok {
				return fmt.Errorf("the CSV base does not describe %s", key)
			}
			if d.Kind != kind {
				return fmt.Errorf("the CSV base gives %s kind %s, the CRD says %s", key, d.Kind, kind)
			}
			owned = append(owned, d)
			delete(described, key)
		}
	}
	if len(described) > 0 {
		return fmt.Errorf("the CSV base describes CRD versions the build does not serve: %v", slices.Sorted(maps.Keys(described)))
	}
	csv.Spec.CustomResourceDefinitions.Owned = owned
	return nil
}

// relatedImages lists the operator image and every operand image of every
// supported product version, so a disconnected mirror copies all of them.
func relatedImages(operator string, profiles versions.Set) []operatorsv1alpha1.RelatedImage {
	related := []operatorsv1alpha1.RelatedImage{{Name: "operator", Image: operator}}
	for _, p := range profiles {
		for _, key := range slices.Sorted(maps.Keys(p.Images)) {
			name := strings.ToLower(strings.TrimSuffix(key, "_IMAGE"))
			related = append(related, operatorsv1alpha1.RelatedImage{
				Name:  fmt.Sprintf("%s-%s", name, strings.ReplaceAll(p.Version, ".", "-")),
				Image: p.Images[key],
			})
		}
	}
	return related
}

func almExamples(samples [][]byte) (string, error) {
	examples := []map[string]any{}
	for _, s := range samples {
		var m map[string]any
		if err := yaml.Unmarshal(s, &m); err != nil {
			return "", fmt.Errorf("sample: %w", err)
		}
		examples = append(examples, m)
	}
	out, err := json.MarshalIndent(examples, "", "  ")
	return string(out), err
}

func dockerfile(annotations map[string]string) []byte {
	var b bytes.Buffer
	b.WriteString("# Generated by tools/bundle. The bundle image holds manifests only.\nFROM scratch\n")
	for _, k := range slices.Sorted(maps.Keys(annotations)) {
		fmt.Fprintf(&b, "LABEL %s=%s\n", k, annotations[k])
	}
	b.WriteString("COPY manifests /manifests/\nCOPY metadata /metadata/\n")
	return b.Bytes()
}

func decodeAll(data []byte) ([]*unstructured.Unstructured, error) {
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*unstructured.Unstructured
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("decode manifests: %w", err)
		}
		if len(m) == 0 {
			continue
		}
		out = append(out, &unstructured.Unstructured{Object: m})
	}
}

func stripNamespace(u *unstructured.Unstructured) *unstructured.Unstructured {
	c := u.DeepCopy()
	c.SetNamespace("")
	return c
}

func fromUnstructured(u *unstructured.Unstructured, into any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(u.Object, into, true)
}

func clusterRoleObject(r *rbacv1.ClusterRole) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(r)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(rbacv1.SchemeGroupVersion.String())
	u.SetKind("ClusterRole")
	return u, nil
}

// marshalObject writes obj as YAML without the empty status and creation
// timestamp a typed object marshals to, so the bundle is byte-for-byte
// reproducible.
func marshalObject(obj any) ([]byte, error) {
	var m map[string]any
	switch o := obj.(type) {
	case *unstructured.Unstructured:
		m = o.DeepCopy().Object
	default:
		var err error
		if m, err = runtime.DefaultUnstructuredConverter.ToUnstructured(obj); err != nil {
			return nil, err
		}
	}
	delete(m, "status")
	pruneNullTimestamps(m)
	return yaml.Marshal(m)
}

// pruneNullTimestamps removes every null creationTimestamp, including those
// in the pod templates of the install strategy.
func pruneNullTimestamps(v any) {
	switch t := v.(type) {
	case map[string]any:
		if ts, ok := t["creationTimestamp"]; ok && ts == nil {
			delete(t, "creationTimestamp")
		}
		for _, child := range t {
			pruneNullTimestamps(child)
		}
	case []any:
		for _, child := range t {
			pruneNullTimestamps(child)
		}
	}
}
