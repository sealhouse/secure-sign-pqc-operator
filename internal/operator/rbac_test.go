package operator

import (
	"context"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	manifests "github.com/sealhouse/secure-sign-pqc-operator/config"
)

// operatorUser is a user that holds only the RBAC the operator ships with:
// config/rbac's generated manager roles and its leader-election Role, bound
// as the bundle binds them, with the operator namespace "system" rewritten
// to opns.
func operatorUser(t *testing.T, opns string) (*rest.Config, *rbacv1.ClusterRoleBinding) {
	t.Helper()
	ctx := context.Background()
	user, err := testEnv.AddUser(envtest.User{Name: "pqc-operator-" + opns}, nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "pqc-operator-" + opns}}
	clusterRole := "pqc-manager-" + opns
	var bindings []rbacv1.RoleBinding
	for _, doc := range rbacDocs(t, "role.yaml", "leader_election_role.yaml") {
		var meta metav1.TypeMeta
		if err := yaml.Unmarshal(doc, &meta); err != nil {
			t.Fatal(err)
		}
		switch meta.Kind {
		case "ClusterRole":
			var r rbacv1.ClusterRole
			if err := yaml.Unmarshal(doc, &r); err != nil {
				t.Fatal(err)
			}
			r.Name = clusterRole
			if err := k8s.Create(ctx, &r); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = k8s.Delete(ctx, &r) })
		case "Role":
			var r rbacv1.Role
			if err := yaml.Unmarshal(doc, &r); err != nil {
				t.Fatal(err)
			}
			r.Namespace = opns
			if err := k8s.Create(ctx, &r); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, rbacv1.RoleBinding{
				Namespace: opns, Name: r.Name,
				RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: r.Name},
				Subjects: subject,
			})
		default:
			t.Fatalf("unexpected %s in config/rbac", meta.Kind)
		}
	}
	for i := range bindings {
		if err := k8s.Create(ctx, &bindings[i]); err != nil {
			t.Fatal(err)
		}
	}
	crb := &rbacv1.ClusterRoleBinding{
		Name:     clusterRole,
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole},
		Subjects: subject,
	}
	if err := k8s.Create(ctx, crb); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = k8s.Delete(ctx, &rbacv1.ClusterRoleBinding{Name: clusterRole})
	})
	return user.Config(), crb
}

func rbacDocs(t *testing.T, files ...string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, f := range files {
		raw, err := manifests.Files.ReadFile("rbac/" + f)
		if err != nil {
			t.Fatal(err)
		}
		for doc := range strings.SplitSeq(string(raw), "\n---") {
			if strings.TrimSpace(strings.TrimPrefix(doc, "---")) != "" {
				out = append(out, []byte(doc))
			}
		}
	}
	return out
}
