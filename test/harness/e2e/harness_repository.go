package e2e

import (
	"fmt"

	"github.com/flightctl/flightctl/api/v1alpha1"
)

func (h *Harness) GetRepository(repositoryName string) (*v1alpha1.Repository, error) {
	response, err := h.Client.GetRepositoryWithResponse(h.Context, repositoryName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}
	if response == nil {
		return nil, fmt.Errorf("repository response is nil")
	}
	return response.JSON200, nil
}
