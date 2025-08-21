package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/flightctl/flightctl/api/v1alpha1"
	"github.com/flightctl/flightctl/test/harness/e2e"
	"github.com/flightctl/flightctl/test/login"
	"github.com/flightctl/flightctl/test/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
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
	var harness *e2e.Harness
	var flightCtlNs string

	resourceYamls := map[string]string{
		"device":     util.GetTestExamplesYamlPath("device.yaml"),
		"fleet":      util.GetTestExamplesYamlPath("fleet.yaml"),
		"repository": util.GetTestExamplesYamlPath("repository-flightctl.yaml"),
	}
	var flightCtlResources []flightCtlResource

	roles := []string{
		adminRoleName,
	}
	roleBindings := []string{
		adminRoleBindingName,
	}

	adminTestLabels := &map[string]string{"test": "rbac-admin"}

	BeforeEach(func() {
		flightCtlNs = os.Getenv("FLIGHTCTL_NS")
		if flightCtlNs == "" {
			Skip("FLIGHTCTL_NS evironment variable should be set")
		}
		harness = e2e.NewTestHarness(suiteCtx)
		flightCtlResources = []flightCtlResource{}
	})

	AfterEach(func() {
		ChangeContext("default")
		login.LoginToAPIWithToken(harness)
		cleanupResources(flightCtlResources, roles, roleBindings, harness, suiteCtx, flightCtlNs)
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
			var err error
			var out string

			By("Creating an admin role and a role binding")
			adminRole, err := createRole(harness.Cluster, flightCtlNs, adminRole)
			Expect(err).ToNot(HaveOccurred())

			adminRoleBinding, err := createRoleBinding(harness.Cluster, flightCtlNs, adminRoleBinding)
			Expect(err).ToNot(HaveOccurred())

			By("Login to the cluster by a user without a role")
			err = loginAsNotAdmin(harness, nonAdminUser, nonAdminUser)
			Expect(err).ToNot(HaveOccurred())

			By("Testing device operations - admin should have full access")
			By("Testing creating a device")
			deviceResource, err := createResource(harness, "device", resourceYamls, flightCtlResources)
			Expect(err).ToNot(HaveOccurred())
			device, ok := deviceResource.(*v1alpha1.Device)
			Expect(ok).To(BeTrue())
			deviceName := device.Metadata.Name

			/*Eventually(func() error {
				out, err = harness.CLI("apply", "-f", resourceYamls["device"])
				return err
			}).Should(BeNil(), "failed to create a Device")
			Expect(out).To(MatchRegexp(`201 Created`))
			device := harness.GetDeviceByYaml(resourceYamls["device"])
			deviceName := device.Metadata.Name
			flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: "device", ResourceName: *deviceName})
			*/
			By("Testing updating a device")
			addTestLabel(device, adminTestLabels)
			deviceData, err := yaml.Marshal(&device)
			Expect(err).ToNot(HaveOccurred())
			logrus.Println("deviceData: ", string(deviceData))
			out, err = harness.CLIWithStdin(string(deviceData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`200 OK`))

			By("Testing getting a specific device")
			_, err = harness.GetResourcesByName("device", *deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific device")

			By("Testing deleting a device")
			_, err = harness.CLI("delete", "device"+"/"+*deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete devices")

			By("Testing fleet operations - admin should have full access")
			By("Testing creating a fleet")
			fleet := harness.GetFleetByYaml(resourceYamls["fleet"])
			fleetName := fleet.Metadata.Name
			Expect(err).ToNot(HaveOccurred())
			fleetData, err := yaml.Marshal(&fleet)
			flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: "fleet", ResourceName: *fleetName})

			logrus.Println("fleetData: ", string(fleetData))
			out, err = harness.CLIWithStdin(string(fleetData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`201 Created`))

			By("Testing updating a fleet")
			addTestLabel(fleet, adminTestLabels)
			fleetData, err = yaml.Marshal(&fleet)
			logrus.Println("fleetData: ", string(fleetData))
			out, err = harness.CLIWithStdin(string(fleetData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`200 OK`))

			By("Testing listing fleets")
			_, err = harness.GetResourcesByName("fleets")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list fleets")

			By("Testing getting a specific fleet")
			_, err = harness.GetResourcesByName("fleet", *fleetName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific fleet")

			By("Testing deleting a fleet")
			_, err = harness.CLI("delete", "fleet", *fleetName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete fleets")

			By("Testing repository operations - admin should have full access")
			By("Testing creating a repository")
			repo := harness.GetRepositoryByYaml(resourceYamls["repository"])
			repoName := repo.Metadata.Name
			repoData, err := yaml.Marshal(&repo)
			Expect(err).ToNot(HaveOccurred())
			flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: "repository", ResourceName: *repoName})

			logrus.Println("repoData: ", string(repoData))
			out, err = harness.CLIWithStdin(string(repoData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`201 Created`))

			By("Testing updating a repository")
			addTestLabel(repo, adminTestLabels)
			repoData, err = yaml.Marshal(&repo)
			logrus.Println("repoData: ", string(repoData))
			out, err = harness.CLIWithStdin(string(repoData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`200 OK`))

			By("Testing listing repositories")
			_, err = harness.GetResourcesByName("repositories")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list repositories")

			By("Testing getting a specific repository")
			_, err = harness.GetResourcesByName("repository", *repoName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific repository")

			By("Testing deleting a repository")
			_, err = harness.CLI("delete", "repository", *repoName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete repositories")

			By("Testing enrollment request operations - admin should have full access")
			By("Testing listing enrollment requests")
			_, err = harness.GetResourcesByName("enrollmentrequests")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list enrollment requests")

			By("Testing events access - admin should have access")
			By("Testing listing events")
			_, err = harness.GetResourcesByName("events")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list events")

			By("Deleting the admin role and role binding")
			ChangeContext("default")
			err = deleteRole(suiteCtx, harness.Cluster, flightCtlNs, adminRole.Name)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete role")
			err = deleteRoleBinding(suiteCtx, harness.Cluster, flightCtlNs, adminRoleBinding.Name)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete role binding")

			By("Testing listing repositories without a role - should not be able to list")
			_, err = harness.GetResourcesByName("repositories")
			Expect(err).To(HaveOccurred(), "A user without a role should not be able to list repositories")
		})
	})
})

func ChangeContext(k8sContext string) {
	cmd := exec.Command("oc", "config", "use-context", k8sContext)
	err := cmd.Run()
	Expect(err).ToNot(HaveOccurred())
}

func addTestLabel(resource interface{}, labels *map[string]string) error {
	switch r := resource.(type) {
	case *v1alpha1.Device:
		r.Metadata.Labels = labels
		return nil
	case *v1alpha1.Fleet:
		r.Metadata.Labels = labels
		return nil
	case *v1alpha1.Repository:
		r.Metadata.Labels = labels
		return nil
	default:
		return fmt.Errorf("unsupported resource type: %T", r)
	}
}

func deleteRoleBinding(ctx context.Context, client kubernetes.Interface, namespace string, roleBindingName string) error {
	return client.RbacV1().RoleBindings(namespace).Delete(ctx, roleBindingName, metav1.DeleteOptions{})
}

func deleteRole(ctx context.Context, client kubernetes.Interface, namespace string, roleName string) error {
	return client.RbacV1().Roles(namespace).Delete(ctx, roleName, metav1.DeleteOptions{})
}

func createRole(kubenetesClient kubernetes.Interface, flightCtlNs string, role *rbacv1.Role) (*rbacv1.Role, error) {
	role, err := kubenetesClient.RbacV1().Roles(flightCtlNs).Create(suiteCtx, role, metav1.CreateOptions{})
	return role, err
}

func createRoleBinding(kubenetesClient kubernetes.Interface, flightCtlNs string, roleBinding *rbacv1.RoleBinding) (*rbacv1.RoleBinding, error) {
	roleBinding, err := kubenetesClient.RbacV1().RoleBindings(flightCtlNs).Create(suiteCtx, roleBinding, metav1.CreateOptions{})
	return roleBinding, err
}

func cleanupResources(flightCtlResources []flightCtlResource, roles []string, roleBindings []string, harness *e2e.Harness, suiteCtx context.Context, flightCtlNs string) {
	for _, resource := range flightCtlResources {
		output, err := harness.CleanUpResource(resource.ResourceType, resource.ResourceName)
		if err != nil {
			logrus.Errorf("Failed to clean up resource %s of resource type %s: %v", resource.ResourceName, resource.ResourceType, err)
		} else {
			logrus.Infof("Cleaned up resource %s of resource type %s: %s", resource.ResourceName, resource.ResourceType, output)
		}
	}

	for _, role := range roles {
		err := deleteRole(suiteCtx, harness.Cluster, flightCtlNs, role)
		if err != nil {
			logrus.Errorf("Failed to delete role %s: %v", role, err)
		} else {
			logrus.Infof("Deleted role %s", role)
		}
	}
	for _, roleBinding := range roleBindings {
		err := deleteRoleBinding(suiteCtx, harness.Cluster, flightCtlNs, roleBinding)
		if err != nil {
			logrus.Errorf("Failed to delete role binding %s: %v", roleBinding, err)
		} else {
			logrus.Infof("Deleted role binding %s", roleBinding)
		}
	}
}

func createResource(harness *e2e.Harness, resourceType string, resourceYamls map[string]string, flightCtlResources []flightCtlResource) (interface{}, error) {
	/*
		out, err := harness.CLI("apply", "-f", resourceYamls[resourceType])
		if err != nil {
			return nil, err
		}
		if strings.Contains(out, "201 Created") || strings.Contains(out, "200 OK") {
			resource := harness.GetDeviceByYaml(resourceYamls[resourceType])
			resourceName := resource.Metadata.Name
			flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: resourceType, ResourceName: *resourceName})
			return resource, nil
		} else {
			logrus.Println("output: ", out)
			return nil, fmt.Errorf("Failed to create a %s", resourceType)
		}
	*/
	var err error
	var out string
	Eventually(func() error {
		out, err = harness.CLI("apply", "-f", resourceYamls[resourceType])
		if err != nil {
			return err
		} else {
			return nil
		}
	}).Should(BeNil(), "failed to create a %s", resourceType)
	Expect(out).To(MatchRegexp(`(201 Created|200 OK)`))
	resource := harness.GetDeviceByYaml(resourceYamls[resourceType])
	resourceName := resource.Metadata.Name
	flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: resourceType, ResourceName: *resourceName})
	return resource, nil
}

/*if strings.Contains(out, "201 Created") || strings.Contains(out, "200 OK") {
			resource := harness.GetDeviceByYaml(resourceYamls[resourceType])
			resourceName := resource.Metadata.Name
			flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: resourceType, ResourceName: *resourceName})
			return resource, nil
		} else {
}

if strings.Contains(out, "201 Created") || strings.Contains(out, "200 OK") {
	resource := harness.GetDeviceByYaml(resourceYamls[resourceType])
	resourceName := resource.Metadata.Name
	flightCtlResources = append(flightCtlResources, flightCtlResource{ResourceType: resourceType, ResourceName: *resourceName})
	return resource, nil
} else {
	logrus.Println("output: ", out)
	return nil, fmt.Errorf("Failed to create a %s", resourceType)
}
}
/*
                                out, err = harness.CLI("apply", "-f", resourceYamls["device"])
                                return err
                        }).Should(BeNil(), "failed to create a Device")
*/

func loginAsNotAdmin(harness *e2e.Harness, user string, password string) error {
	ChangeContext("default")
	cmd := exec.Command("bash", "-c", "oc whoami --show-server")
	kubernetesApiEndpoint, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), "Failed to get kubernetes api endpoint")
	loginCommand := fmt.Sprintf("oc login -u %s -p %s %s", user, password, string(kubernetesApiEndpoint))
	cmd = exec.Command("bash", "-c", loginCommand)
	err = cmd.Run()
	Expect(err).ToNot(HaveOccurred())

	method := login.LoginToAPIWithToken(harness)
	Expect(method).ToNot(Equal(login.AuthDisabled))
	if method == login.AuthDisabled {
		return errors.New("Login is disabled")
	}
	return nil
}

