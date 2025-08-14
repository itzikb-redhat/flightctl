package rbac_test

import (
	"context"
	"testing"

	"github.com/flightctl/flightctl/test/util"
	testutil "github.com/flightctl/flightctl/test/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestRbac(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RBAC E2E Suite")
}

var (
	suiteCtx context.Context
)

var _ = BeforeSuite(func() {
	suiteCtx = testutil.InitSuiteTracerForGinkgo("RBAC E2E Suite")

	// Check if ACM is installed before running any tests
	isAcmInstalled, err := util.IsAcmInstalled()
	if err != nil {
		logrus.Warnf("An error happened %v", err)
	}
	if !isAcmInstalled {
		Skip("Skipping test suite because ACM is not installed.")
	}
})
