package main

import (
	"errors"

	"github.com/locktivity/epack-collector-jumpcloud/internal/collector"
	"github.com/locktivity/epack-collector-jumpcloud/internal/jumpcloud"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "jumpcloud",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects JumpCloud identity, access, and device posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()

	config := collector.Config{
		OrgID:    getString(cfg, "org_id"),
		OnStatus: ctx.Status,
	}

	apiKey := ctx.Secret("JUMPCLOUD_API_KEY")
	if apiKey == "" {
		return componentsdk.NewConfigError("JUMPCLOUD_API_KEY is required")
	}

	client := jumpcloud.NewClient(apiKey, config.OrgID)
	c := collector.New(config, client)

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return classifyError(err)
	}

	artifacts := []componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/jumpcloud.json",
		},
	}

	if idpPosture := posture.ToIDPPosture(); idpPosture != nil {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{
			Data:   idpPosture,
			Schema: "evidencepack/idp-posture@v1",
			Path:   "artifacts/jumpcloud.idp-posture.json",
		})
	}

	return ctx.Emit(artifacts)
}

func classifyError(err error) error {
	if errors.Is(err, jumpcloud.ErrUnauthorized) {
		return componentsdk.NewAuthError("unauthorized: %v", err)
	}
	return componentsdk.NewNetworkError("collecting posture: %v", err)
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}
