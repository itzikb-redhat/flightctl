package e2e

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (h *Harness) CreateRole(ctx context.Context, kubenetesClient kubernetes.Interface, flightCtlNs string, role *rbacv1.Role) (*rbacv1.Role, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if role == nil {
		return nil, errors.New("role parameter cannot be nil")
	}
	if flightCtlNs == "" {
		return nil, errors.New("namespace cannot be empty")
	}

	role, err := kubenetesClient.RbacV1().Roles(flightCtlNs).Create(ctx, role, metav1.CreateOptions{})
	return role, err
}

func (h *Harness) CreateRoleBinding(ctx context.Context, kubenetesClient kubernetes.Interface, flightCtlNs string, roleBinding *rbacv1.RoleBinding) (*rbacv1.RoleBinding, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}
	if roleBinding == nil {
		return nil, errors.New("roleBinding cannot be nil")
	}
	if flightCtlNs == "" {
		return nil, errors.New("namespace cannot be empty")
	}
	roleBinding, err := kubenetesClient.RbacV1().RoleBindings(flightCtlNs).Create(ctx, roleBinding, metav1.CreateOptions{})
	return roleBinding, err
}

func (h *Harness) CleanupRoles(roles []string, roleBindings []string, suiteCtx context.Context, flightCtlNs string) {
	for _, role := range roles {
		err := h.DeleteRole(suiteCtx, h.Cluster, flightCtlNs, role)
		if err != nil {
			logrus.Errorf("Failed to delete role %s: %v", role, err)
		} else {
			logrus.Infof("Deleted role %s", role)
		}
	}
	for _, roleBinding := range roleBindings {
		err := h.DeleteRoleBinding(suiteCtx, h.Cluster, flightCtlNs, roleBinding)
		if err != nil {
			logrus.Errorf("Failed to delete role binding %s: %v", roleBinding, err)
		} else {
			logrus.Infof("Deleted role binding %s", roleBinding)
		}
	}
}

func (h *Harness) DeleteRoleBinding(ctx context.Context, client kubernetes.Interface, namespace string, roleBindingName string) error {
	return client.RbacV1().RoleBindings(namespace).Delete(ctx, roleBindingName, metav1.DeleteOptions{})
}

func (h *Harness) DeleteRole(ctx context.Context, client kubernetes.Interface, namespace string, roleName string) error {
	return client.RbacV1().Roles(namespace).Delete(ctx, roleName, metav1.DeleteOptions{})
}
