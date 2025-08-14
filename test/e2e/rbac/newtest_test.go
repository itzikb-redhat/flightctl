package rbac_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"sigs.k8s.io/yaml"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/flightctl/flightctl/test/harness/e2e"
	"github.com/flightctl/flightctl/test/login"
	"github.com/flightctl/flightctl/test/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RBAC Authorization Tests", Label("rbac", "authorization"), func() {
	var harness *e2e.Harness
	flightCtlNs := os.Getenv("FLIGHTCTL_NS")

	BeforeEach(func() {
		harness = e2e.NewTestHarness(suiteCtx)
		/*		if login.LoginToAPIWithToken(harness) == login.AuthDisabled {
					Skip("Authentication is disabled for this deployment")
				}
		*/

	})

	AfterEach(func() {
		//		harness.Cleanup(true)
		//	err := harness.CleanUpAllResources()
		//	Expect(err).ToNot(HaveOccurred())
		//	harness.Cleanup(false) // do not print console on error
	})

	Context("FlightCtl Admin Role", func() {
		It("should have full access to all resources and operations", Label("sanity", "78400"), func() {
			var err error
			var out string
			var (
				deviceYamlPath = util.GetTestExamplesYamlPath("device.yaml")
			)
			//randString, err := util.RandString()
			Expect(err).ToNot(HaveOccurred(), "Failed to generate random string")

			By("Creating an admin role and role binding")
			adminRole := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rbac-test-admin-role",
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
					Name:      "rbac-test-admin-role-binding",
					Namespace: flightCtlNs,
				},
			}
			adminRoleBinding.RoleRef = rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "rbac-test-admin-role",
			}
			adminRoleBinding.Subjects = []rbacv1.Subject{
				{
					Kind: "User",
					Name: "demouser1",
				},
			}

			kubenetesClient := harness.Cluster
			adminRole, err = kubenetesClient.RbacV1().Roles(flightCtlNs).Create(suiteCtx, adminRole, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			defer DeleteRole(suiteCtx, kubenetesClient, flightCtlNs, adminRole)

			adminRoleBinding, err = kubenetesClient.RbacV1().RoleBindings(flightCtlNs).Create(suiteCtx, adminRoleBinding, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			defer DeleteRoleBinding(suiteCtx, kubenetesClient, flightCtlNs, adminRoleBinding)

			By("Login to the cluster by a user without a role")
			// Must be changed
			cmd := exec.Command("bash", "-c", "oc whoami --show-server")
			kubernetesApiEndpoint, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), "Failed to get kubernetes api endpoint")

			loginCommand := fmt.Sprintf("oc login -u %s -p %s %s", nonAdminUser, nonAdminUser, string(kubernetesApiEndpoint))
			cmd = exec.Command("bash", "-c", loginCommand)
			err = cmd.Run()
			Expect(err).ToNot(HaveOccurred())
			defer ChangeContext("default")

			method := login.LoginToAPIWithToken(harness)
			Expect(method).ToNot(Equal(login.AuthDisabled))

			By("Testing device operations - admin should have full access")
			/*		deviceName := "rbac-test-device-admin-" + randString
					deviceYaml := util.GetTestExamplesYamlPath("device.yaml")
					output, err := harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName))
					Expect(err).ToNot(HaveOccurred(), "Admin should be able to create devices: stdout=%s, stderr=%s", output, err)
					Eventually(func() error {
						_, err := harness.GetDevice(deviceName)
						return err
					}, util.TIMEOUT, util.POLLING).Should(Succeed())
			*/

			/*			By("Testing updating a device")
						_, err = harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName), "--set", "metadata.labels.test=rbac-admin")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to update devices")
			*/
			Eventually(func() error {
				out, err = harness.CLI("apply", "-f", deviceYamlPath)
				return err
			}).Should(BeNil(), "failed to apply Device")
			Expect(out).To(MatchRegexp(`(200 OK|201 Created)`))
			device := harness.GetDeviceByYaml(deviceYamlPath)

			device.Metadata.Labels = &map[string]string{"test": "rbac-admin"}
			deviceName := device.Metadata.Name
			deviceData, err := yaml.Marshal(&device)
			Expect(err).ToNot(HaveOccurred())

			By("Testing updating a device")
			logrus.Println("deviceData: ", string(deviceData))
			out, err = harness.CLIWithStdin(string(deviceData), "apply", "-f", "-")
			Expect(err).ToNot(HaveOccurred())
			Expect(out).To(MatchRegexp(`200 OK`))

			By("Testing getting a specific device")
			_, err = harness.CLI("get", "device"+"/"+*deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific device")

			By("Testing deleting a device")
			_, err = harness.CLI("delete", "device"+"/"+*deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete devices")

			/*			By("Testing fleet operations - admin should have full access")
						Expect(err).ToNot(HaveOccurred(), "Failed to generate random string")
						fleetName := "rbac-test-fleet-admin-" + randString
						fleetYaml := util.GetTestExamplesYamlPath("fleet.yaml")

						By("Testing creating a fleet")
						output, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName))
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to create fleets: output=%s, err=%s", output, err)
						Eventually(func() error {
							_, err := harness.GetFleet(fleetName)
							return err
						}, util.TIMEOUT, util.POLLING).Should(Succeed())

						By("Testing listing fleets")
						_, err = harness.CLI("get", "fleets")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to list fleets")

						By("Testing getting a specific fleet")
						_, err = harness.CLI("get", "fleet", fleetName)
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific fleet")

						/*By("Testing updating a fleet")
						_, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName), "--set", "metadata.labels.test=rbac-admin")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to update fleets")

						By("Testing deleting a fleet")
						_, err = harness.CLI("delete", "fleet", fleetName)
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete fleets")

						By("Testing repository operations - admin should have full access")
						repoName := "rbac-test-repo-admin-" + randString
						repoYaml := util.GetTestExamplesYamlPath("repository.yaml")

						By("Testing creating a repository")
						output, err = harness.CLI("apply", "-f", repoYaml, "--set", fmt.Sprintf("metadata.name=%s", repoName))
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to create repositories: stdout=%s, stderr=%s", output, err)

						By("Testing listing repositories")
						_, err = harness.CLI("get", "repositories")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to list repositories")

						By("Testing deleting a repository")
						_, err = harness.CLI("delete", "repository", repoName)
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete repositories")

						By("Testing enrollment request operations - admin should have full access")
						_, err = harness.CLI("get", "enrollmentrequests")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to list enrollment requests")

						By("Testing events access - admin should have access")
						_, err = harness.CLI("get", "events")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to list events")

						By("Testing labels access - admin should have access")
						_, err = harness.CLI("get", "labels")
						Expect(err).ToNot(HaveOccurred(), "Admin should be able to list labels")
			*/
		})
	})
})

func ChangeContext(k8sContext string) {
	cmd := exec.Command("bash", "-c", "oc config use-context "+k8sContext)
	err := cmd.Run()
	Expect(err).ToNot(HaveOccurred())
}

func DeleteRoleBinding(ctx context.Context, client kubernetes.Interface, namespace string, roleBinding *rbacv1.RoleBinding) {
	client.RbacV1().RoleBindings(namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
}

func DeleteRole(ctx context.Context, client kubernetes.Interface, namespace string, role *rbacv1.Role) {
	client.RbacV1().Roles(namespace).Delete(ctx, role.Name, metav1.DeleteOptions{})
}
