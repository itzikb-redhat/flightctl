package rbac_test

import (
	//"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/flightctl/flightctl/test/harness/e2e"
	"github.com/flightctl/flightctl/test/login"

	//"github.com/flightctl/flightctl/test/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RBAC Authorization Tests", Label("rbac", "authorization"), func() {
	var harness *e2e.Harness

	BeforeEach(func() {
		harness = e2e.NewTestHarness()
		if login.LoginToAPIWithToken(harness) == login.AuthDisabled {
			Skip("Authentication is disabled for this deployment")
		}
	})

	AfterEach(func() {
		harness.Cleanup(true)
	})

	Context("FlightCtl Admin Role", func() {
		It("should have full access to all resources and operations", Label("sanity", "78400"), func() {
			By("Creating an admin role")
			adminRole := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name: "rbac-test-admin-role",
				},
			}
			adminRole.Rules = []rbacv1.PolicyRule{
				{
					APIGroups: []string{"flightctl.io"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			}
			client := harness.Cluster
			adminRole, err := client.RbacV1().Roles("flightctl.io").Create(suiteCtx, adminRole, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			By("Setting up admin user context")
			// Admin role has '*' verbs on '*' resources in flightctl.io group

			/*
				######### Start ###########
				By("Login to flightctl as a user with the admin role")
				login.WithPassword("demouser1", "demouser1")

				By("Testing device operations - admin should have full access")
				deviceName := "rbac-test-device-admin-" + util.RandString()
				deviceYaml := util.GetTestExamplesYamlPath("device.yaml")

				// Create device
				stdout, stderr, err := harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName))
				Expect(err).ToNot(HaveOccurred(), "Admin should be able to create devices: stdout=%s, stderr=%s", stdout, stderr)
				Eventually(func() error {
					_, err := harness.GetDevice(deviceName)
					return err
				}, util.TIMEOUT, util.POLLING).Should(Succeed())

				// List devices
				_, _, err = harness.CLI("get", "devices")
				Expect(err).ToNot(HaveOccurred(), "Admin should be able to list devices")
			*/
		})
		// ########## End ###########
		/*
			// Get specific device
			_, _, err = harness.CLI("get", "device", deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to get specific device")

			// Update device
			_, _, err = harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName), "--set", "metadata.labels.test=rbac-admin")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to update devices")

			// Delete device
			_, _, err = harness.CLI("delete", "device", deviceName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete devices")

			By("Testing fleet operations - admin should have full access")
			fleetName := "rbac-test-fleet-admin-" + util.RandString()
			fleetYaml := util.GetTestExamplesYamlPath("fleet.yaml")

			// Create fleet
			stdout, stderr, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName))
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to create fleets: stdout=%s, stderr=%s", stdout, stderr)
			Eventually(func() error {
				_, err := harness.GetFleet(fleetName)
				return err
			}, util.TIMEOUT, util.POLLING).Should(Succeed())

			// List fleets
			_, _, err = harness.CLI("get", "fleets")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list fleets")

			// Delete fleet
			_, _, err = harness.CLI("delete", "fleet", fleetName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete fleets")

			By("Testing repository operations - admin should have full access")
			repoName := "rbac-test-repo-admin-" + util.RandString()
			repoYaml := util.GetTestExamplesYamlPath("repository.yaml")

			// Create repository
			stdout, stderr, err = harness.CLI("apply", "-f", repoYaml, "--set", fmt.Sprintf("metadata.name=%s", repoName))
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to create repositories: stdout=%s, stderr=%s", stdout, stderr)

			// List repositories
			_, _, err = harness.CLI("get", "repositories")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list repositories")

			// Delete repository
			_, _, err = harness.CLI("delete", "repository", repoName)
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to delete repositories")

			By("Testing enrollment request operations - admin should have full access")
			// List enrollment requests
			_, _, err = harness.CLI("get", "enrollmentrequests")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list enrollment requests")

			By("Testing events access - admin should have access")
			// List events
			_, _, err = harness.CLI("get", "events")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list events")

			By("Testing labels access - admin should have access")
			// List labels
			_, _, err = harness.CLI("get", "labels")
			Expect(err).ToNot(HaveOccurred(), "Admin should be able to list labels")
		*/
	})
})

/*
	Context("FlightCtl Viewer Role", func() {
		It("should have read-only access to specific resources", Label("sanity", "78401"), func() {
			By("Setting up viewer user context")
			// Viewer role has 'get' and 'list' verbs on devices, fleets, resourcesyncs

			By("Testing device read operations - viewer should have access")
			// Create a device first as admin for viewer to read
			deviceName := "rbac-test-device-viewer-" + util.RandString()
			deviceYaml := util.GetTestExamplesYamlPath("device.yaml")

			// Assume admin context for setup
			stdout, stderr, err := harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName))
			Expect(err).ToNot(HaveOccurred(), "Setup: Admin should be able to create device: stdout=%s, stderr=%s", stdout, stderr)
			Eventually(func() error {
				_, err := harness.GetDevice(deviceName)
				return err
			}, util.TIMEOUT, util.POLLING).Should(Succeed())

			// Switch to viewer context and test read operations
			By("Testing viewer can list devices")
			_, _, err = harness.CLI("get", "devices")
			Expect(err).ToNot(HaveOccurred(), "Viewer should be able to list devices")

			By("Testing viewer can get specific device")
			_, _, err = harness.CLI("get", "device", deviceName)
			Expect(err).ToNot(HaveOccurred(), "Viewer should be able to get specific device")

			By("Testing viewer cannot create devices")
			newDeviceName := "rbac-test-device-viewer-denied-" + util.RandString()
			_, _, err = harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", newDeviceName))
			Expect(err).To(HaveOccurred(), "Viewer should not be able to create devices")

			By("Testing viewer cannot delete devices")
			_, _, err = harness.CLI("delete", "device", deviceName)
			Expect(err).To(HaveOccurred(), "Viewer should not be able to delete devices")

			By("Testing fleet read operations - viewer should have access")
			fleetName := "rbac-test-fleet-viewer-" + util.RandString()
			fleetYaml := util.GetTestExamplesYamlPath("fleet.yaml")

			// Create fleet as admin
			stdout, stderr, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName))
			Expect(err).ToNot(HaveOccurred(), "Setup: Admin should be able to create fleet: stdout=%s, stderr=%s", stdout, stderr)

			// Test viewer access
			_, _, err = harness.CLI("get", "fleets")
			Expect(err).ToNot(HaveOccurred(), "Viewer should be able to list fleets")

			_, _, err = harness.CLI("get", "fleet", fleetName)
			Expect(err).ToNot(HaveOccurred(), "Viewer should be able to get specific fleet")

			By("Testing viewer cannot create fleets")
			newFleetName := "rbac-test-fleet-viewer-denied-" + util.RandString()
			_, _, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", newFleetName))
			Expect(err).To(HaveOccurred(), "Viewer should not be able to create fleets")

			By("Testing viewer cannot access repositories")
			_, _, err = harness.CLI("get", "repositories")
			Expect(err).To(HaveOccurred(), "Viewer should not have access to repositories")

			By("Testing viewer cannot access enrollment requests")
			_, _, err = harness.CLI("get", "enrollmentrequests")
			Expect(err).To(HaveOccurred(), "Viewer should not have access to enrollment requests")

			// Cleanup
			harness.CLI("delete", "device", deviceName)
			harness.CLI("delete", "fleet", fleetName)
		})
	})

	Context("FlightCtl Operator Role", func() {
		It("should have full CRUD access to devices, fleets, resourcesyncs and read-only access to others", Label("sanity", "78402"), func() {
			By("Setting up operator user context")
			// Operator role has full CRUD on devices, fleets, resourcesyncs + console access on devices + read access to repositories and templateversions

			By("Testing device operations - operator should have full CRUD access")
			deviceName := "rbac-test-device-operator-" + util.RandString()
			deviceYaml := util.GetTestExamplesYamlPath("device.yaml")

			// Create device
			stdout, stderr, err := harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName))
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to create devices: stdout=%s, stderr=%s", stdout, stderr)
			Eventually(func() error {
				_, err := harness.GetDevice(deviceName)
				return err
			}, util.TIMEOUT, util.POLLING).Should(Succeed())

			// Update device
			_, _, err = harness.CLI("apply", "-f", deviceYaml, "--set", fmt.Sprintf("metadata.name=%s", deviceName), "--set", "metadata.labels.test=rbac-operator")
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to update devices")

			// List and get devices
			_, _, err = harness.CLI("get", "devices")
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to list devices")

			_, _, err = harness.CLI("get", "device", deviceName)
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to get specific device")

			// Delete device
			_, _, err = harness.CLI("delete", "device", deviceName)
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to delete devices")

			By("Testing fleet operations - operator should have full CRUD access")
			fleetName := "rbac-test-fleet-operator-" + util.RandString()
			fleetYaml := util.GetTestExamplesYamlPath("fleet.yaml")

			// Create fleet
			stdout, stderr, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName))
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to create fleets: stdout=%s, stderr=%s", stdout, stderr)

			// Update fleet
			_, _, err = harness.CLI("apply", "-f", fleetYaml, "--set", fmt.Sprintf("metadata.name=%s", fleetName), "--set", "metadata.labels.test=rbac-operator")
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to update fleets")

			// Delete fleet
			_, _, err = harness.CLI("delete", "fleet", fleetName)
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to delete fleets")

			By("Testing repository read access - operator should have read-only access")
			// Create repository as admin first
			repoName := "rbac-test-repo-operator-" + util.RandString()
			repoYaml := util.GetTestExamplesYamlPath("repository.yaml")

			// Assume admin context for setup
			stdout, stderr, err = harness.CLI("apply", "-f", repoYaml, "--set", fmt.Sprintf("metadata.name=%s", repoName))
			Expect(err).ToNot(HaveOccurred(), "Setup: Admin should be able to create repository: stdout=%s, stderr=%s", stdout, stderr)

			// Test operator read access
			_, _, err = harness.CLI("get", "repositories")
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to list repositories")

			_, _, err = harness.CLI("get", "repository", repoName)
			Expect(err).ToNot(HaveOccurred(), "Operator should be able to get specific repository")

			By("Testing operator cannot create/modify/delete repositories")
			newRepoName := "rbac-test-repo-operator-denied-" + util.RandString()
			_, _, err = harness.CLI("apply", "-f", repoYaml, "--set", fmt.Sprintf("metadata.name=%s", newRepoName))
			Expect(err).To(HaveOccurred(), "Operator should not be able to create repositories")

			_, _, err = harness.CLI("delete", "repository", repoName)
			Expect(err).To(HaveOccurred(), "Operator should not be able to delete repositories")

			By("Testing operator cannot access enrollment requests")
			_, _, err = harness.CLI("get", "enrollmentrequests")
			Expect(err).To(HaveOccurred(), "Operator should not have access to enrollment requests")

			// Cleanup
			harness.CLI("delete", "repository", repoName)
		})
	})

	Context("FlightCtl Installer Role", func() {
		It("should have access only to enrollment requests and certificate signing requests", Label("sanity", "78403"), func() {
			By("Setting up installer user context")
			// Installer role has get/list on enrollmentrequests, post on enrollmentrequests/approval, get/list/create on certificatesigningrequests

			By("Testing enrollment request operations - installer should have access")
			// List enrollment requests
			_, _, err := harness.CLI("get", "enrollmentrequests")
			Expect(err).ToNot(HaveOccurred(), "Installer should be able to list enrollment requests")

			By("Testing installer cannot access devices")
			_, _, err = harness.CLI("get", "devices")
			Expect(err).To(HaveOccurred(), "Installer should not have access to devices")

			By("Testing installer cannot access fleets")
			_, _, err = harness.CLI("get", "fleets")
			Expect(err).To(HaveOccurred(), "Installer should not have access to fleets")

			By("Testing installer cannot access repositories")
			_, _, err = harness.CLI("get", "repositories")
			Expect(err).To(HaveOccurred(), "Installer should not have access to repositories")

			By("Testing installer cannot access resourcesyncs")
			_, _, err = harness.CLI("get", "resourcesyncs")
			Expect(err).To(HaveOccurred(), "Installer should not have access to resourcesyncs")

			By("Testing installer cannot access events")
			_, _, err = harness.CLI("get", "events")
			Expect(err).To(HaveOccurred(), "Installer should not have access to events")

			By("Testing installer cannot access labels")
			_, _, err = harness.CLI("get", "labels")
			Expect(err).To(HaveOccurred(), "Installer should not have access to labels")
		})
	})

	Context("Cross-role Permission Validation", func() {
		DescribeTable("Resource access permissions",
			func(role, resource, operation string, shouldSucceed bool) {
				By(fmt.Sprintf("Testing %s role access to %s for %s operation", role, resource, operation))

				var stdout, stderr string
				var err error

				switch operation {
				case "list":
					stdout, stderr, err = harness.CLI("get", resource)
				case "create":
					// Use appropriate YAML file for the resource
					yamlFile := getResourceYamlFile(resource)
					resourceName := fmt.Sprintf("rbac-test-%s-%s-%s", resource, role, util.RandString())
					stdout, stderr, err = harness.CLI("apply", "-f", yamlFile, "--set", fmt.Sprintf("metadata.name=%s", resourceName))
				case "delete":
					// Create resource first, then delete
					yamlFile := getResourceYamlFile(resource)
					resourceName := fmt.Sprintf("rbac-test-%s-%s-%s", resource, role, util.RandString())
					harness.CLI("apply", "-f", yamlFile, "--set", fmt.Sprintf("metadata.name=%s", resourceName))
					stdout, stderr, err = harness.CLI("delete", resource, resourceName)
				}

				if shouldSucceed {
					Expect(err).ToNot(HaveOccurred(), "Operation should succeed: stdout=%s, stderr=%s", stdout, stderr)
				} else {
					Expect(err).To(HaveOccurred(), "Operation should fail: stdout=%s, stderr=%s", stdout, stderr)
				}
			},
			// Admin role - should have access to everything
			Entry("Admin can list devices", "admin", "devices", "list", true),
			Entry("Admin can create devices", "admin", "devices", "create", true),
			Entry("Admin can delete devices", "admin", "devices", "delete", true),
			Entry("Admin can list fleets", "admin", "fleets", "list", true),
			Entry("Admin can create fleets", "admin", "fleets", "create", true),
			Entry("Admin can delete fleets", "admin", "fleets", "delete", true),
			Entry("Admin can list repositories", "admin", "repositories", "list", true),
			Entry("Admin can create repositories", "admin", "repositories", "create", true),
			Entry("Admin can delete repositories", "admin", "repositories", "delete", true),
			Entry("Admin can list enrollmentrequests", "admin", "enrollmentrequests", "list", true),

			// Viewer role - read-only access to specific resources
			Entry("Viewer can list devices", "viewer", "devices", "list", true),
			Entry("Viewer cannot create devices", "viewer", "devices", "create", false),
			Entry("Viewer cannot delete devices", "viewer", "devices", "delete", false),
			Entry("Viewer can list fleets", "viewer", "fleets", "list", true),
			Entry("Viewer cannot create fleets", "viewer", "fleets", "create", false),
			Entry("Viewer cannot delete fleets", "viewer", "fleets", "delete", false),
			Entry("Viewer cannot list repositories", "viewer", "repositories", "list", false),
			Entry("Viewer cannot list enrollmentrequests", "viewer", "enrollmentrequests", "list", false),

			// Operator role - full CRUD on devices/fleets, read-only on repositories
			Entry("Operator can list devices", "operator", "devices", "list", true),
			Entry("Operator can create devices", "operator", "devices", "create", true),
			Entry("Operator can delete devices", "operator", "devices", "delete", true),
			Entry("Operator can list fleets", "operator", "fleets", "list", true),
			Entry("Operator can create fleets", "operator", "fleets", "create", true),
			Entry("Operator can delete fleets", "operator", "fleets", "delete", true),
			Entry("Operator can list repositories", "operator", "repositories", "list", true),
			Entry("Operator cannot create repositories", "operator", "repositories", "create", false),
			Entry("Operator cannot delete repositories", "operator", "repositories", "delete", false),
			Entry("Operator cannot list enrollmentrequests", "operator", "enrollmentrequests", "list", false),

			// Installer role - only enrollment and CSR access
			Entry("Installer cannot list devices", "installer", "devices", "list", false),
			Entry("Installer cannot list fleets", "installer", "fleets", "list", false),
			Entry("Installer cannot list repositories", "installer", "repositories", "list", false),
			Entry("Installer can list enrollmentrequests", "installer", "enrollmentrequests", "list", true),
		)
	})

	Context("Token Expiration and Refresh", func() {
		It("should handle token expiration gracefully", Label("sanity", "78404"), func() {
			By("Marking client access token as expired")
			err := harness.MarkClientAccessTokenExpired()
			Expect(err).ToNot(HaveOccurred())

			By("Simulating network failure to prevent token refresh")
			restoreNetwork, err := harness.SimulateNetworkFailureForCLI("auth-server-ip", 443)
			Expect(err).ToNot(HaveOccurred())
			defer func() { _ = restoreNetwork() }()

			By("Attempting API operation - should fail due to expired token and no refresh")
			_, _, err = harness.CLI("get", "devices")
			Expect(err).To(HaveOccurred(), "Operation should fail with expired token and no network")

			By("Restoring network connectivity")
			err = restoreNetwork()
			Expect(err).ToNot(HaveOccurred())

			By("Attempting API operation again - should succeed after token refresh")
			Eventually(func() error {
				_, _, err := harness.CLI("get", "devices")
				return err
			}, util.TIMEOUT, util.POLLING).Should(Succeed(), "Operation should succeed after token refresh")
		})
	})

	Context("API Endpoint Authorization", func() {
		It("should properly protect all API endpoints based on resource/action mapping", Label("sanity", "78405"), func() {
			testCases := []struct {
				endpoint    string
				method      string
				resource    string
				action      string
				description string
			}{
				{"/api/v1/devices", "GET", "devices", "list", "List devices"},
				{"/api/v1/devices", "POST", "devices", "create", "Create device"},
				{"/api/v1/devices/test-device", "GET", "devices", "get", "Get specific device"},
				{"/api/v1/devices/test-device", "PUT", "devices", "update", "Update device"},
				{"/api/v1/devices/test-device", "PATCH", "devices", "patch", "Patch device"},
				{"/api/v1/devices/test-device", "DELETE", "devices", "delete", "Delete device"},
				{"/api/v1/devices/test-device/status", "GET", "devices/status", "get", "Get device status"},
				{"/api/v1/devices/test-device/console", "GET", "devices/console", "get", "Get device console"},
				{"/api/v1/fleets", "GET", "fleets", "list", "List fleets"},
				{"/api/v1/fleets", "POST", "fleets", "create", "Create fleet"},
				{"/api/v1/fleets/test-fleet", "GET", "fleets", "get", "Get specific fleet"},
				{"/api/v1/fleets/test-fleet/templateversions", "GET", "fleets/templateversions", "list", "List template versions"},
				{"/api/v1/repositories", "GET", "repositories", "list", "List repositories"},
				{"/api/v1/repositories", "POST", "repositories", "create", "Create repository"},
				{"/api/v1/enrollmentrequests", "GET", "enrollmentrequests", "list", "List enrollment requests"},
				{"/api/v1/enrollmentrequests/test-er/approval", "POST", "enrollmentrequests/approval", "create", "Approve enrollment request"},
				{"/api/v1/events", "GET", "events", "list", "List events"},
				{"/api/v1/labels", "GET", "labels", "list", "List labels"},
			}

			for _, tc := range testCases {
				By(fmt.Sprintf("Testing %s: %s %s", tc.description, tc.method, tc.endpoint))

				// Use HTTP client to test direct API access
				req, err := http.NewRequest(tc.method, harness.APIEndpoint()+tc.endpoint, nil)
				Expect(err).ToNot(HaveOccurred())

				// Add auth token
				token, err := harness.GetAuthToken()
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Authorization", "Bearer "+token)

				client := &http.Client{}
				resp, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				// Verify that authorization is being checked
				// Non-auth endpoints should not return 401/403 for invalid tokens
				// Auth-protected endpoints should return 401/403 or succeed based on permissions
				Expect(resp.StatusCode).ToNot(Equal(500), "Should not have internal server error for %s", tc.endpoint)
			}
		})
	})

	Context("Role Binding Validation", func() {
		It("should validate that role bindings are properly configured", Label("sanity", "78406"), func() {
			By("Verifying flightctl-admin role exists")
			adminRole, err := harness.GetK8sRole("flightctl-admin")
			Expect(err).ToNot(HaveOccurred(), "flightctl-admin role should exist")
			Expect(adminRole.Rules).To(HaveLen(1), "Admin role should have one rule")
			Expect(adminRole.Rules[0].Verbs).To(ContainElement("*"), "Admin role should have all verbs")
			Expect(adminRole.Rules[0].Resources).To(ContainElement("*"), "Admin role should have access to all resources")

			By("Verifying flightctl-viewer role exists")
			viewerRole, err := harness.GetK8sRole("flightctl-viewer")
			Expect(err).ToNot(HaveOccurred(), "flightctl-viewer role should exist")
			Expect(adminRole.Rules).To(Not(BeEmpty()), "Viewer role should have rules")

			// Check that viewer role only has get/list verbs
			for _, rule := range viewerRole.Rules {
				for _, verb := range rule.Verbs {
					Expect([]string{"get", "list"}).To(ContainElement(verb), "Viewer role should only have get/list verbs")
				}
			}

			By("Verifying flightctl-operator role exists")
			operatorRole, err := harness.GetK8sRole("flightctl-operator")
			Expect(err).ToNot(HaveOccurred(), "flightctl-operator role should exist")
			Expect(operatorRole.Rules).To(Not(BeEmpty()), "Operator role should have rules")

			By("Verifying flightctl-installer role exists")
			installerRole, err := harness.GetK8sRole("flightctl-installer")
			Expect(err).ToNot(HaveOccurred(), "flightctl-installer role should exist")
			Expect(installerRole.Rules).To(Not(BeEmpty()), "Installer role should have rules")

			// Check that installer role only has access to enrollment requests and CSRs
			for _, rule := range installerRole.Rules {
				for _, resource := range rule.Resources {
					Expect([]string{"enrollmentrequests", "enrollmentrequests/approval", "certificatesigningrequests"}).To(ContainElement(resource),
						"Installer role should only have access to enrollment and CSR resources")
				}
			}
		})
	})
})
*/
// Helper function to get the appropriate YAML file for a resource type

/*
func getResourceYamlFile(resource string) string {
	switch resource {
	case "devices":
		return util.GetTestExamplesYamlPath("device.yaml")
	case "fleets":
		return util.GetTestExamplesYamlPath("fleet.yaml")
	case "repositories":
		return util.GetTestExamplesYamlPath("repository.yaml")
	case "resourcesyncs":
		return util.GetTestExamplesYamlPath("resourcesync.yaml")
	default:
		return util.GetTestExamplesYamlPath("device.yaml") // Default fallback
	}
}
*/
