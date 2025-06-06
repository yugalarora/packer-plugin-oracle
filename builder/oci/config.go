// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:generate packer-sdc mapstructure-to-hcl2 -type Config,CreateVNICDetails,ListImagesRequest,FlexShapeConfig

package oci

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/hashicorp/packer-plugin-sdk/common"
	"github.com/hashicorp/packer-plugin-sdk/communicator"
	packersdk "github.com/hashicorp/packer-plugin-sdk/packer"
	"github.com/hashicorp/packer-plugin-sdk/pathing"
	"github.com/hashicorp/packer-plugin-sdk/template/config"
	"github.com/hashicorp/packer-plugin-sdk/template/interpolate"
	ocicommon "github.com/oracle/oci-go-sdk/v65/common"
	ociauth "github.com/oracle/oci-go-sdk/v65/common/auth"
)

type CreateVNICDetails struct {
	// fields that can be specified under "create_vnic_details"
	AssignPublicIp *bool `mapstructure:"assign_public_ip" required:"false"`
	// HCL cannot be decoded into an interface so for HCL templates you must use the DefinedTagsJson option,
	// To be used with https://www.packer.io/docs/templates/hcl_templates/functions/encoding/jsonencode
	// ref: https://github.com/hashicorp/hcl/issues/291#issuecomment-496347585
	DefinedTagsJson string `mapstructure:"defined_tags_json" required:"false"`
	// For JSON templates we keep the map[string]map[string]interface{}
	DefinedTags         map[string]map[string]interface{} `mapstructure:"defined_tags" mapstructure-to-hcl2:",skip" required:"false"`
	DisplayName         *string                           `mapstructure:"display_name" required:"false"`
	FreeformTags        map[string]string                 `mapstructure:"tags" required:"false"`
	HostnameLabel       *string                           `mapstructure:"hostname_label" required:"false"`
	NsgIds              []string                          `mapstructure:"nsg_ids" required:"false"`
	PrivateIp           *string                           `mapstructure:"private_ip" required:"false"`
	SkipSourceDestCheck *bool                             `mapstructure:"skip_source_dest_check" required:"false"`
	SubnetId            *string                           `mapstructure:"subnet_id" required:"false"`
}

type ListImagesRequest struct {
	// fields that can be specified under "base_image_filter"
	CompartmentId          *string `mapstructure:"compartment_id"`
	DisplayName            *string `mapstructure:"display_name"`
	DisplayNameSearch      *string `mapstructure:"display_name_search"`
	OperatingSystem        *string `mapstructure:"operating_system"`
	OperatingSystemVersion *string `mapstructure:"operating_system_version"`
	Shape                  *string `mapstructure:"shape"`
}

type FlexShapeConfig struct {
	Ocpus                   *float32 `mapstructure:"ocpus" required:"false"`
	MemoryInGBs             *float32 `mapstructure:"memory_in_gbs" required:"false"`
	BaselineOcpuUtilization *string  `mapstructure:"baseline_ocpu_utilization" required:"false"`
}

type Config struct {
	common.PackerConfig `mapstructure:",squash"`
	Comm                communicator.Config `mapstructure:",squash"`

	configProvider ocicommon.ConfigurationProvider

	// Instance Principals (OPTIONAL)
	// If set to true the following can't have non empty values
	// - AccessCfgFile
	// - AccessCfgFileAccount
	// - UserID
	// - TenancyID
	// - Region
	// - Fingerprint
	// - KeyFile
	// - PassPhrase
	InstancePrincipals bool `mapstructure:"use_instance_principals"`

	// Resource Principal Token (OPTIONAL)
	// If set to true, the OCI SDK will use resource principal token for authentication.
	// This is useful if you are running Packer within an OCI Function.
	// This option is mutually exclusive with use_instance_principals and other credential-specific configurations.
	UseResourcePrincipalToken bool `mapstructure:"use_resource_principal_token" required:"false"`

	// If true, Packer will not create the image. Useful for setting to `true`
	// during a build test stage. Default `false`.
	SkipCreateImage bool `mapstructure:"skip_create_image" required:"false"`

	AccessCfgFile        string `mapstructure:"access_cfg_file"`
	AccessCfgFileAccount string `mapstructure:"access_cfg_file_account"`

	// Access config overrides
	UserID       string `mapstructure:"user_ocid"`
	TenancyID    string `mapstructure:"tenancy_ocid"`
	Region       string `mapstructure:"region"`
	Fingerprint  string `mapstructure:"fingerprint"`
	KeyFile      string `mapstructure:"key_file"`
	PassPhrase   string `mapstructure:"pass_phrase"`
	UsePrivateIP bool   `mapstructure:"use_private_ip"`

	SecurityTokenFilePath string `mapstructure:"security_token_file"`
	AvailabilityDomain    string `mapstructure:"availability_domain"`
	CompartmentID         string `mapstructure:"compartment_ocid"`

	// Image
	BaseImageID        string            `mapstructure:"base_image_ocid"`
	BaseImageFilter    ListImagesRequest `mapstructure:"base_image_filter"`
	ImageName          string            `mapstructure:"image_name"`
	ImageCompartmentID string            `mapstructure:"image_compartment_ocid"`
	LaunchMode         string            `mapstructure:"image_launch_mode"`
	NicAttachmentType  string            `mapstructure:"nic_attachment_type"`

	// Instance
	InstanceName *string           `mapstructure:"instance_name"`
	InstanceTags map[string]string `mapstructure:"instance_tags"`
	// HCL cannot be decoded into an interface so for HCL templates you must use the InstanceDefinedTagsJson option,
	// To be used with https://www.packer.io/docs/templates/hcl_templates/functions/encoding/jsonencode
	// ref: https://github.com/hashicorp/hcl/issues/291#issuecomment-496347585
	InstanceDefinedTagsJson                       string                            `mapstructure:"instance_defined_tags_json" required:"false"`
	InstanceDefinedTags                           map[string]map[string]interface{} `mapstructure:"instance_defined_tags" mapstructure-to-hcl2:",skip"`
	Shape                                         string                            `mapstructure:"shape"`
	ShapeConfig                                   FlexShapeConfig                   `mapstructure:"shape_config"`
	BootVolumeSizeInGBs                           int64                             `mapstructure:"disk_size"`
	InstanceOptionsAreLegacyImdsEndpointsDisabled *bool                             `mapstructure:"instance_options_are_legacy_imds_endpoints_disabled" required:"false"`

	// Metadata optionally contains custom metadata key/value pairs provided in the
	// configuration. While this can be used to set metadata["user_data"] the explicit
	// "user_data" and "user_data_file" values will have precedence.
	// An instance's metadata can be obtained from at http://169.254.169.254 on the
	// launched instance.
	Metadata map[string]string `mapstructure:"metadata"`

	// UserData and UserDataFile file are both optional and mutually exclusive.
	UserData     string `mapstructure:"user_data"`
	UserDataFile string `mapstructure:"user_data_file"`

	// Networking
	SubnetID          string            `mapstructure:"subnet_ocid"`
	CreateVnicDetails CreateVNICDetails `mapstructure:"create_vnic_details"`

	// Tagging
	Tags map[string]string `mapstructure:"tags"`
	// HCL cannot be decoded into an interface so for HCL templates you must use the DefinedTagsJson option,
	// To be used with https://www.packer.io/docs/templates/hcl_templates/functions/encoding/jsonencode
	// ref: https://github.com/hashicorp/hcl/issues/291#issuecomment-496347585
	DefinedTagsJson string `mapstructure:"defined_tags_json" required:"false"`
	// For JSON templates we keep the map[string]map[string]interface{}
	DefinedTags map[string]map[string]interface{} `mapstructure:"defined_tags" required:"false" mapstructure-to-hcl2:",skip"`

	ctx interpolate.Context
}

func (c *Config) ConfigProvider() ocicommon.ConfigurationProvider {
	return c.configProvider
}

func (c *Config) Prepare(raws ...interface{}) error {

	// Decode from template
	err := config.Decode(c, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &c.ctx,
	}, raws...)
	if err != nil {
		return fmt.Errorf("Failed to mapstructure Config: %+v", err)
	}

	var errs *packersdk.MultiError
	if es := c.Comm.Prepare(&c.ctx); len(es) > 0 {
		errs = packersdk.MultiErrorAppend(errs, es...)
	}

	if c.InstanceDefinedTagsJson != "" {
		if err := json.Unmarshal([]byte(c.InstanceDefinedTagsJson), &c.InstanceDefinedTags); err != nil {
			return fmt.Errorf("Failed to unmarshal 'instance_defined_tags_json': %s", err.Error())
		}
	}

	if c.DefinedTagsJson != "" {
		if err := json.Unmarshal([]byte(c.DefinedTagsJson), &c.DefinedTags); err != nil {
			return fmt.Errorf("Failed to unmarshal 'defined_tags': %s", err.Error())
		}
	}

	if c.CreateVnicDetails.DefinedTagsJson != "" {
		if err := json.Unmarshal([]byte(c.CreateVnicDetails.DefinedTagsJson), &c.CreateVnicDetails.DefinedTags); err != nil {
			return fmt.Errorf("Failed to unmarshal 'defined_tags': %s", err.Error())
		}
	}

	var tenancyOCID string

	// Determine active authentication method and check for mutual exclusivity
	authMethods := 0
	if c.InstancePrincipals {
		authMethods++
	}
	if c.UseResourcePrincipalToken {
		authMethods++
	}

	// Check if any standard auth parameters are set, which would imply a third auth method.
	// This is a simplified check; detailed conflicts are handled within each auth method's block.
	hasStandardAuthConfig := c.AccessCfgFile != "" || c.AccessCfgFileAccount != "" ||
		c.UserID != "" || c.TenancyID != "" || c.Region != "" ||
		c.Fingerprint != "" || c.KeyFile != "" || c.PassPhrase != "" || c.SecurityTokenFilePath != ""

	if !c.InstancePrincipals && !c.UseResourcePrincipalToken && hasStandardAuthConfig {
		authMethods++
	} else if (c.InstancePrincipals || c.UseResourcePrincipalToken) && hasStandardAuthConfig {
		// If using principal auth AND standard auth fields are set, it's a conflict handled below.
		// No need to increment authMethods here as it's covered by specific checks.
	}


	if authMethods > 1 {
		errs = packersdk.MultiErrorAppend(errs, errors.New("Configuration error: 'use_instance_principals', 'use_resource_principal_token', and standard credential configurations (e.g., 'user_ocid', 'key_file') are mutually exclusive. Please use only one authentication method."))
		// No need to proceed with auth provider setup if multiple methods are ambiguously implied.
	} else if c.UseResourcePrincipalToken {
		// Resource Principal Token Authentication
		var message string = " cannot be present when use_resource_principal_token is set to true."
		if c.InstancePrincipals { // Explicit check against InstancePrincipals
			errs = packersdk.MultiErrorAppend(errs, errors.New("'use_instance_principals'"+message))
		}
		if c.AccessCfgFile != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("access_cfg_file"+message))
		}
		if c.AccessCfgFileAccount != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("access_cfg_file_account"+message))
		}
		if c.UserID != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("user_ocid"+message))
		}
		if c.TenancyID != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("tenancy_ocid"+message))
		}
		if c.Region != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("region"+message+" (use OCI_RESOURCE_PRINCIPAL_REGION environment variable)"))
		}
		if c.Fingerprint != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("fingerprint"+message))
		}
		if c.KeyFile != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("key_file"+message+" (use OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM environment variable)"))
		}
		if c.PassPhrase != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("pass_phrase"+message))
		}
		if c.SecurityTokenFilePath != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("security_token_file"+message+" (use OCI_RESOURCE_PRINCIPAL_RPST environment variable)"))
		}

		requiredEnvVars := []string{
			"OCI_RESOURCE_PRINCIPAL_VERSION",
			"OCI_RESOURCE_PRINCIPAL_RPST",
			"OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM",
			"OCI_RESOURCE_PRINCIPAL_REGION",
		}
		for _, envVar := range requiredEnvVars {
			if os.Getenv(envVar) == "" {
				errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Required environment variable %s is not set for Resource Principal Token authentication", envVar))
			}
		}

		// Attempt to create provider only if no previous errors related to RPT config
		if c.configProvider == nil && len(errs.Errors) == 0 { // Only attempt if no prior errors
			provider, err := ociauth.ResourcePrincipalConfigurationProvider()
			if err != nil {
				errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Failed to create Resource Principal Configuration Provider: %w", err))
			} else if provider == nil { // New check
				errs = packersdk.MultiErrorAppend(errs, errors.New("Resource principal configuration provider returned nil without an error"))
			} else {
				c.configProvider = provider
				// TenancyOCID might be needed for some validations later, try to get it
				// It's okay if it fails here, as the provider itself is the primary goal
				currentTenancyOCID, errTenancy := provider.TenancyOCID()
				if errTenancy != nil {
					// Log or handle error if TenancyOCID is critical for RP flow immediately
					// For now, consistent with previous logic, we don't make this a hard error for errs
					log.Printf("[WARN] Could not get TenancyOCID from resource principal provider: %v", errTenancy)
				} else if currentTenancyOCID == "" {
					log.Printf("[WARN] Resource principal provider returned an empty TenancyOCID.")
				}
				// Assign to tenancyOCID only if it's successfully retrieved for later validation/use
				// This ensures tenancyOCID variable is only populated with a valid, non-empty string.
				if currentTenancyOCID != "" {
					tenancyOCID = currentTenancyOCID
				}
				// Set region from env var if not set by provider (should be set by env for RPT)
				if c.Region == "" && os.Getenv("OCI_RESOURCE_PRINCIPAL_REGION") != "" {
					c.Region = os.Getenv("OCI_RESOURCE_PRINCIPAL_REGION")
				}
			}
		}
	} else if c.InstancePrincipals {
		// Instance Principals Authentication
		// We could go through all keys in one go and report that the below set
		// of keys cannot coexist with use_instance_principals but decided to
		// split them and report them seperately so that the user sees the specific
		// key involved.
		var message string = " cannot be present when use_instance_principals is set to true."
		// This block needs to ensure mutual exclusivity with standard auth parameters
		if c.AccessCfgFile != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("access_cfg_file"+message))
		}
		if c.AccessCfgFileAccount != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("access_cfg_file_account"+message))
		}
		if c.UserID != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("user_ocid"+message))
		}
		if c.TenancyID != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("tenancy_ocid"+message))
		}
		if c.Region != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("region"+message))
		}
		if c.Fingerprint != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("fingerprint"+message))
		}
		if c.KeyFile != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("key_file"+message))
		}
		if c.PassPhrase != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("pass_phrase"+message))
		}
		if c.SecurityTokenFilePath != "" {
			errs = packersdk.MultiErrorAppend(errs, errors.New("security_token_file"+message))
		}

		// Attempt to create provider only if no previous errors related to InstancePrincipals config
		if len(errs.Errors) == 0 && c.configProvider == nil {
			provider, err := ociauth.InstancePrincipalConfigurationProvider()
			if err != nil {
				errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Failed to create Instance Principal Configuration Provider: %w", err))
			} else {
				c.configProvider = provider
				currentTenancyOCID, err := provider.TenancyOCID()
				if err != nil {
					errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Failed to get TenancyOCID from Instance Principal: %w", err))
				} else if currentTenancyOCID == "" {
					errs = packersdk.MultiErrorAppend(errs, errors.New("TenancyOCID not found via Instance Principal"))
				} else {
					tenancyOCID = currentTenancyOCID
				}
				// Set region from provider if not set
				if c.Region == "" {
					currentRegion, _ := provider.Region()
					if currentRegion != "" {
						c.Region = currentRegion
					}
				}
			}
		}
	} else if authMethods == 0 || hasStandardAuthConfig { // Standard Authentication (file, explicit config, or SDK environment variables)
		// This block executes if no principal auth is set, or if principal auth is set but also standard auth fields (error handled above or by SDK).
		// Or if authMethods is 0, meaning we default to standard.
		// Determine where the SDK config is located
		if c.AccessCfgFile == "" {
			defaultPath, defaultPathErr := getDefaultOCISettingsPath()
			if defaultPathErr == nil {
				c.AccessCfgFile = defaultPath
			} else {
				// Only log if it's not a simple "not found" for the default path,
				// or if other auth methods aren't being tried.
				// If explicit user/tenancy/etc. are given, not finding default oci config is fine.
				if !(c.UserID != "" && c.TenancyID != "" && c.KeyFile != "" && c.Fingerprint != "") {
					log.Println("Default OCI settings file not found and not all direct auth parameters provided. Relying on SDK environment variables or other auth methods if configured.")
				}
			}
		}


		if c.AccessCfgFileAccount == "" {
			c.AccessCfgFileAccount = "DEFAULT"
		}

		var keyContent []byte
		if c.KeyFile != "" {
			expandedPath, pathErr := pathing.ExpandUser(c.KeyFile)
			if pathErr != nil {
				errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Error expanding KeyFile path %s: %w", c.KeyFile, pathErr))
			} else {
				var readErr error
				keyContent, readErr = ioutil.ReadFile(expandedPath)
				if readErr != nil {
					errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Error reading KeyFile %s: %w", expandedPath, readErr))
				}
			}
		}

		var fileProvider ocicommon.ConfigurationProvider
		if c.AccessCfgFile != "" {
			// Check if AccessCfgFile actually exists before trying to load it
			if _, statErr := os.Stat(c.AccessCfgFile); statErr == nil {
				// PassPhrase might be empty, which is fine for ConfigurationProviderFromFileWithProfile
				fileProvider, _ = ocicommon.ConfigurationProviderFromFileWithProfile(c.AccessCfgFile, c.AccessCfgFileAccount, c.PassPhrase)
			} else if !os.IsNotExist(statErr) {
				// Log error if it's not a "file does not exist" type of error
				errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Error accessing OCI config file %s: %w", c.AccessCfgFile, statErr))
			}
		}

		// Prefer explicitly set region, then from file, then from env, then default
		if c.Region == "" {
			if fileProvider != nil {
				regionFromFile, _ := fileProvider.Region()
				if regionFromFile != "" {
					c.Region = regionFromFile
				}
			}
			if c.Region == "" && os.Getenv("OCI_REGION") != "" {
				c.Region = os.Getenv("OCI_REGION")
			}
			if c.Region == "" && os.Getenv("OCI_CONFIG_FILE") == "" && c.AccessCfgFile == "" { // Only default if no other region source from file/env
				c.Region = "us-phoenix-1" // Default if not found anywhere else
			}
		}
		
		// Create a raw provider from explicitly set config values
		rawProvider := ocicommon.NewRawConfigurationProvider(c.TenancyID, c.UserID, c.Region, c.Fingerprint, string(keyContent), &c.PassPhrase)

		providers := []ocicommon.ConfigurationProvider{rawProvider}
		if fileProvider != nil {
			providers = append(providers, fileProvider)
		}
		providers = append(providers, ocicommon.DefaultConfigProvider()) // Checks environment variables

		composedProvider, compErr := ocicommon.ComposingConfigurationProvider(providers)
		if compErr != nil {
			errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Failed to create Composing Configuration Provider: %w", compErr))
		} else {
			c.configProvider = composedProvider
		}

		// Validate essential fields if using standard auth and provider was successfully created
		if c.configProvider != nil {
			currentTenancyID, err := c.configProvider.TenancyOCID()
			if err != nil || currentTenancyID == "" {
				errs = packersdk.MultiErrorAppend(errs, errors.New("tenancy_ocid must be specified (config, OCI config file, or OCI_TENANCY env var)"))
			} else {
				tenancyOCID = currentTenancyID // Used for defaulting CompartmentID
			}

			// Region check (critical for API calls)
			currentRegion, err := c.configProvider.Region()
			if err != nil || currentRegion == "" {
				errs = packersdk.MultiErrorAppend(errs, errors.New("region must be specified (config, OCI config file, OCI_REGION env var, or default)"))
			} else {
				c.Region = currentRegion // Ensure c.Region is updated from provider if it resolved one
			}

			// Fingerprint and UserOCID are generally required if not using session token auth
			// The SDK's DefaultConfigProvider handles session tokens (OCI_SECURITY_TOKEN_FILE, OCI_AUTH_TOKEN_FILE)
			// So, these checks are conditional. If these are empty, the SDK might still succeed with a token.
			// We rely on actual API calls to fail if auth is truly broken.
			// However, if KeyFile is provided, Fingerprint is expected.
			if c.KeyFile != "" {
				if fp, _ := c.configProvider.KeyFingerprint(); fp == "" {
					errs = packersdk.MultiErrorAppend(errs, errors.New("fingerprint must be specified when 'key_file' is provided (config, OCI config file, or OCI_FINGERPRINT env var)"))
				}
			}
			if user, _ := c.configProvider.UserOCID(); user == "" && (c.KeyFile != "" || c.Fingerprint != "") { // If key/fingerprint implies API key auth
				errs = packersdk.MultiErrorAppend(errs, errors.New("user_ocid must be specified for API key auth (config, OCI config file, or OCI_USER env var)"))
			}
		}
	}


	// Final check for provider
	if c.configProvider == nil && len(errs.Errors) == 0 { // if no errors so far, but provider is still nil
		errs = packersdk.MultiErrorAppend(errs, errors.New("Could not initialize OCI configuration provider. Please check your authentication settings."))
	}


	// Common validations that rely on tenancyOCID or region being determined
	if tenancyOCID == "" && c.configProvider != nil && len(errs.Errors) == 0 { // Try to get tenancyOCID again if not set
		currentTenancyOCID, err := c.configProvider.TenancyOCID()
		if err == nil && currentTenancyOCID != "" {
			tenancyOCID = currentTenancyOCID
		} else if len(errs.Errors) == 0 { // Avoid adding redundant error if auth already failed
			errs = packersdk.MultiErrorAppend(errs, errors.New("Could not determine Tenancy OCID from any authentication method."))
		}
	}
	if c.Region == "" && c.configProvider != nil && len(errs.Errors) == 0 { // Try to get region again
		currentRegion, err := c.configProvider.Region()
		if err == nil && currentRegion != "" {
			c.Region = currentRegion
		} else if len(errs.Errors) == 0 {
			errs = packersdk.MultiErrorAppend(errs, errors.New("Could not determine Region from any authentication method."))
		}
	}


	if c.AvailabilityDomain == "" {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'availability_domain' must be specified"))
	}

	if c.CompartmentID == "" && tenancyOCID != "" {
		c.CompartmentID = tenancyOCID
	}

	if c.ImageCompartmentID == "" {
		c.ImageCompartmentID = c.CompartmentID
	}

	if c.Shape == "" {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'shape' must be specified"))
	}

	if strings.HasSuffix(c.Shape, "Flex") {
		if c.ShapeConfig.Ocpus == nil {
			errs = packersdk.MultiErrorAppend(
				errs, errors.New("'Ocpus' must be specified when using flexible shapes"))
		}
	}

	if c.ShapeConfig.MemoryInGBs != nil && c.ShapeConfig.Ocpus == nil {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'Ocpus' must be specified if memory_in_gbs is specified"))
	}

	if c.ShapeConfig.BaselineOcpuUtilization != nil && c.ShapeConfig.Ocpus == nil {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'Ocpus' must be specified if baseline_ocpu_utilization is specified"))
	}

	if (c.SubnetID == "") && (c.CreateVnicDetails.SubnetId == nil) {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'subnet_ocid' must be specified"))
	}

	if c.CreateVnicDetails.SubnetId == nil {
		c.CreateVnicDetails.SubnetId = &c.SubnetID
	} else if (*c.CreateVnicDetails.SubnetId != c.SubnetID) && (c.SubnetID != "") {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'create_vnic_details[subnet]' must match 'subnet_ocid' if both are specified"))
	}

	if (c.BaseImageID == "") && (c.BaseImageFilter == ListImagesRequest{}) {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'base_image_ocid' or 'base_image_filter' must be specified"))
	}

	if c.BaseImageFilter.CompartmentId == nil {
		c.BaseImageFilter.CompartmentId = &c.CompartmentID
	}

	if c.BaseImageFilter.Shape == nil {
		c.BaseImageFilter.Shape = &c.Shape
	}

	// Validate tag lengths. TODO (hlowndes) maximum number of tags allowed.
	if c.Tags != nil {
		for k, v := range c.Tags {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if len(k) > 100 {
				errs = packersdk.MultiErrorAppend(
					errs, fmt.Errorf("Tag key length too long. Maximum 100 but found %d. Key: %s", len(k), k))
			}
			if len(k) == 0 {
				errs = packersdk.MultiErrorAppend(
					errs, errors.New("Tag key empty in config"))
			}
			if len(v) > 100 {
				errs = packersdk.MultiErrorAppend(
					errs, fmt.Errorf("Tag value length too long. Maximum 100 but found %d. Key: %s", len(v), k))
			}
			if len(v) == 0 {
				errs = packersdk.MultiErrorAppend(
					errs, errors.New("Tag value empty in config"))
			}
		}
	}

	if c.ImageName == "" {
		name, err := interpolate.Render("packer-{{timestamp}}", nil)
		if err != nil {
			errs = packersdk.MultiErrorAppend(errs,
				fmt.Errorf("unable to parse image name: %s", err))
		} else {
			c.ImageName = name
		}
	}

	// Optional UserData config
	if c.UserData != "" && c.UserDataFile != "" {
		errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Only one of user_data or user_data_file can be specified."))
	} else if c.UserDataFile != "" {
		if _, err := os.Stat(c.UserDataFile); err != nil {
			errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("user_data_file not found: %s", c.UserDataFile))
		}
	}
	// read UserDataFile into string.
	if c.UserDataFile != "" {
		fiData, err := ioutil.ReadFile(c.UserDataFile)
		if err != nil {
			errs = packersdk.MultiErrorAppend(errs, fmt.Errorf("Problem reading user_data_file: %s", err))
		}
		c.UserData = string(fiData)
	}
	// Test if UserData is encoded already, and if not, encode it
	if c.UserData != "" {
		if _, err := base64.StdEncoding.DecodeString(c.UserData); err != nil {
			log.Printf("[DEBUG] base64 encoding user data...")
			c.UserData = base64.StdEncoding.EncodeToString([]byte(c.UserData))
		}
	}

	// Validate LaunchMode
	if c.LaunchMode != "" && c.LaunchMode != "NATIVE" && c.LaunchMode != "EMULATED" && c.LaunchMode != "PARAVIRTUALIZED" && c.LaunchMode != "CUSTOM" {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("LaunchMode must be one of NATIVE, EMULATED, PARAVIRTUALIZED, or CUSTOM"))
	}

	// Validate NicAttachmentType
	if c.NicAttachmentType != "" && c.NicAttachmentType != "VFIO" && c.NicAttachmentType != "E1000" && c.NicAttachmentType != "PARAVIRTUALIZED" {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("NicAttachmentType must be one of VFIO, E1000, or PARAVIRTUALIZED"))
	}

	// Set default boot volume size to 50 if not set
	// Check if size set is allowed by OCI
	if c.BootVolumeSizeInGBs != 0 && (c.BootVolumeSizeInGBs < 50 || c.BootVolumeSizeInGBs > 16384) {
		errs = packersdk.MultiErrorAppend(
			errs, errors.New("'disk_size' must be between 50 and 16384 GBs"))
	}

	if errs != nil && len(errs.Errors) > 0 {
		return errs
	}

	return nil
}

// getDefaultOCISettingsPath uses os/user to compute the default
// config file location ($HOME/.oci/config).
func getDefaultOCISettingsPath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	if u.HomeDir == "" {
		return "", fmt.Errorf("Unable to determine the home directory for the current user.")
	}

	path := filepath.Join(u.HomeDir, ".oci", "config")
	if _, err := os.Stat(path); err != nil {
		return "", err
	}

	return path, nil
}

