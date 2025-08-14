package rbac_test

import (
	"context"
	"testing"

	testutil "github.com/flightctl/flightctl/test/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	nonAdminUser = "demouser1"
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
})
