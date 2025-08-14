package rbac_test

import (
	"context"
	"fmt"

	"github.com/flightctl/flightctl/test/harness/e2e"
	"github.com/flightctl/flightctl/test/login"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	nonAdminUser         = "demouser1"
	adminRoleName        = "rbac-test-admin-role"
	adminRoleBindingName = "rbac-test-admin-role-binding"
)

type flightCtlResource struct {
	ResourceType string
	ResourceName string
}

var _ = Describe("RBAC Authorization Tests", Label("rbac", "authorization"), func() {
	var (
		harness           *e2e.Harness
		suiteCtx          context.Context
		defaultK8sContext string
		k8sApiEndpoint    string
	)

	roles := []string{
		adminRoleName,
	}
	roleBindings := []string{
		adminRoleBindingName,
	}
	adminTestLabels := &map[string]string{"test": "rbac-admin"}

	BeforeEach(func() {
		var err error
		// Get the harness and context set up by the suite
		harness = e2e.GetWorkerHarness()
		suiteCtx = e2e.GetWorkerContext()

		// Get the default K8s context
		defaultK8sContext, err = harness.GetDefaultK8sContext()
		Expect(err).ToNot(HaveOccurred(), "Failed to get default K8s context")
		k8sApiEndpoint, err = harness.GetK8sApiEndpoint(defaultK8sContext)
		Expect(err).ToNot(HaveOccurred(), "Failed to get Kubernetes API endpoint")
	})

	AfterEach(func() {
		harness.ChangeK8sContext(defaultK8sContext)
		login.LoginToAPIWithToken(harness)
		harness.CleanupRoles(roles, roleBindings, suiteCtx, flightCtlNs)
	})

	Context("FlightCtl Admin Role", func() {
		adminRole := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      adminRoleName,
				Namespace: flightCtlNs,
			},
		}
		adminRole.Rules = []rbacv1.PolicyRule{
			{
				APIGroups: []string{"flightctl.io"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		}
		adminRoleBinding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      adminRoleBindingName,
				Namespace: flightCtlNs,
			},
		}
		adminRoleBinding.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     adminRoleName,
		}
		adminRoleBinding.Subjects = []rbacv1.Subject{
			{
				Kind: "User",
				Name: nonAdminUser,
			},
		}

		It("should have full access to all resources and operations", Label("sanity", "83842"), func() {
			By("Creating an admin role and a role binding")
			createdAdminRole, err := harness.CreateRole(suiteCtx, harness.Cluster, flightCtlNs, adminRole)
			Expect(err).ToNot(HaveOccurred())
			createdAdminRoleBinding, err := harness.CreateRoleBinding(suiteCtx, harness.Cluster, flightCtlNs, adminRoleBinding)
			Expect(err).ToNot(HaveOccurred())

			By("Login to the cluster by a user without a role")
			err = login.LoginAsNonAdmin(harness, nonAdminUser, nonAdminUser, defaultK8sContext, k8sApiEndpoint)
			Expect(err).ToNot(HaveOccurred())

			for _, resourceType := range []string{"device", "fleet", "repository"} {
				By(fmt.Sprintf("Testing %s operations - admin should have full access", resourceType))
				By(fmt.Sprintf("Testing creating a %s", resourceType))
				resourceName, resourceData, err := harness.CreateResource(resourceType)
				Expect(err).ToNot(HaveOccurred())

				By(fmt.Sprintf("Testing updating a %s", resourceType))
				updatedResourceData, err := harness.AddLabelsToYAML(string(resourceData), *adminTestLabels)
				Expect(err).ToNot(HaveOccurred())
				_, err = harness.CLIWithStdin(updatedResourceData, "apply", "-f", "-")
				Expect(err).ToNot(HaveOccurred())

				By(fmt.Sprintf("Testing getting a specific %s", resourceType))
				_, err = harness.GetResourcesByName(resourceType, resourceName)
				Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Admin should be able to get specific %s", resourceType))

				By(fmt.Sprintf("Testing listing %s", resourceType))
				_, err = harness.GetResourcesByName(resourceType)
				Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Admin should be able to list %s", resourceType))

				By(fmt.Sprintf("Testing deleting a %s", resourceType))
				_, err = harness.CLI("delete", resourceType, resourceName)
				Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Admin should be able to delete %s", resourceType))
			}

			for _, resourceType := range []string{"enrollmentrequests", "events"} {
				By(fmt.Sprintf("Testing %s operations - admin should have full access", resourceType))
				By(fmt.Sprintf("Testing listing %s", resourceType))
				_, err = harness.GetResourcesByName(resourceType)
				Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Admin should be able to list %s", resourceType))
			}

			By("Deleting the admin role and role binding")
			harness.ChangeK8sContext(defaultK8sContext)
			err = harness.DeleteRole(suiteCtx, harness.Cluster, flightCtlNs, createdAdminRole.Name)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete role")
			err = harness.DeleteRoleBinding(suiteCtx, harness.Cluster, flightCtlNs, createdAdminRoleBinding.Name)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete role binding")

			By("Testing listing repositories without a role - should not be able to list")
			_, err = harness.GetResourcesByName("repositories")
			Expect(err).To(HaveOccurred(), "A user without a role should not be able to list repositories")
		})
	})
})
