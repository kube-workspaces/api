
# v1alpha1

```go
import "github.com/kube-workspaces/controller/api/v1alpha1"
```

Package v1alpha1 contains API Schema definitions for the v1alpha1 API group. \+kubebuilder:object:generate=true \+groupName=kubeworkspaces.io

## Index

- [Variables](<#variables>)
- [type AuthConfig](<#AuthConfig>)
  - [func \(in \*AuthConfig\) DeepCopy\(\) \*AuthConfig](<#AuthConfig.DeepCopy>)
  - [func \(in \*AuthConfig\) DeepCopyInto\(out \*AuthConfig\)](<#AuthConfig.DeepCopyInto>)
  - [func \(in \*AuthConfig\) DeepCopyObject\(\) runtime.Object](<#AuthConfig.DeepCopyObject>)
- [type AuthConfigList](<#AuthConfigList>)
  - [func \(in \*AuthConfigList\) DeepCopy\(\) \*AuthConfigList](<#AuthConfigList.DeepCopy>)
  - [func \(in \*AuthConfigList\) DeepCopyInto\(out \*AuthConfigList\)](<#AuthConfigList.DeepCopyInto>)
  - [func \(in \*AuthConfigList\) DeepCopyObject\(\) runtime.Object](<#AuthConfigList.DeepCopyObject>)
- [type AuthConfigSpec](<#AuthConfigSpec>)
  - [func \(in \*AuthConfigSpec\) DeepCopy\(\) \*AuthConfigSpec](<#AuthConfigSpec.DeepCopy>)
  - [func \(in \*AuthConfigSpec\) DeepCopyInto\(out \*AuthConfigSpec\)](<#AuthConfigSpec.DeepCopyInto>)
- [type AuthConfigStatus](<#AuthConfigStatus>)
  - [func \(in \*AuthConfigStatus\) DeepCopy\(\) \*AuthConfigStatus](<#AuthConfigStatus.DeepCopy>)
  - [func \(in \*AuthConfigStatus\) DeepCopyInto\(out \*AuthConfigStatus\)](<#AuthConfigStatus.DeepCopyInto>)
- [type AuthorizationConfig](<#AuthorizationConfig>)
  - [func \(in \*AuthorizationConfig\) DeepCopy\(\) \*AuthorizationConfig](<#AuthorizationConfig.DeepCopy>)
  - [func \(in \*AuthorizationConfig\) DeepCopyInto\(out \*AuthorizationConfig\)](<#AuthorizationConfig.DeepCopyInto>)
- [type BootstrapAdminConfig](<#BootstrapAdminConfig>)
  - [func \(in \*BootstrapAdminConfig\) DeepCopy\(\) \*BootstrapAdminConfig](<#BootstrapAdminConfig.DeepCopy>)
  - [func \(in \*BootstrapAdminConfig\) DeepCopyInto\(out \*BootstrapAdminConfig\)](<#BootstrapAdminConfig.DeepCopyInto>)
- [type Image](<#Image>)
  - [func \(in \*Image\) DeepCopy\(\) \*Image](<#Image.DeepCopy>)
  - [func \(in \*Image\) DeepCopyInto\(out \*Image\)](<#Image.DeepCopyInto>)
  - [func \(in \*Image\) DeepCopyObject\(\) runtime.Object](<#Image.DeepCopyObject>)
- [type ImageCredentials](<#ImageCredentials>)
  - [func \(in \*ImageCredentials\) DeepCopy\(\) \*ImageCredentials](<#ImageCredentials.DeepCopy>)
  - [func \(in \*ImageCredentials\) DeepCopyInto\(out \*ImageCredentials\)](<#ImageCredentials.DeepCopyInto>)
- [type ImageEnvVar](<#ImageEnvVar>)
  - [func \(in \*ImageEnvVar\) DeepCopy\(\) \*ImageEnvVar](<#ImageEnvVar.DeepCopy>)
  - [func \(in \*ImageEnvVar\) DeepCopyInto\(out \*ImageEnvVar\)](<#ImageEnvVar.DeepCopyInto>)
- [type ImageLink](<#ImageLink>)
  - [func \(in \*ImageLink\) DeepCopy\(\) \*ImageLink](<#ImageLink.DeepCopy>)
  - [func \(in \*ImageLink\) DeepCopyInto\(out \*ImageLink\)](<#ImageLink.DeepCopyInto>)
- [type ImageList](<#ImageList>)
  - [func \(in \*ImageList\) DeepCopy\(\) \*ImageList](<#ImageList.DeepCopy>)
  - [func \(in \*ImageList\) DeepCopyInto\(out \*ImageList\)](<#ImageList.DeepCopyInto>)
  - [func \(in \*ImageList\) DeepCopyObject\(\) runtime.Object](<#ImageList.DeepCopyObject>)
- [type ImagePort](<#ImagePort>)
  - [func \(in \*ImagePort\) DeepCopy\(\) \*ImagePort](<#ImagePort.DeepCopy>)
  - [func \(in \*ImagePort\) DeepCopyInto\(out \*ImagePort\)](<#ImagePort.DeepCopyInto>)
- [type ImageProxyConfig](<#ImageProxyConfig>)
  - [func \(in \*ImageProxyConfig\) DeepCopy\(\) \*ImageProxyConfig](<#ImageProxyConfig.DeepCopy>)
  - [func \(in \*ImageProxyConfig\) DeepCopyInto\(out \*ImageProxyConfig\)](<#ImageProxyConfig.DeepCopyInto>)
- [type ImageSpec](<#ImageSpec>)
  - [func \(in \*ImageSpec\) DeepCopy\(\) \*ImageSpec](<#ImageSpec.DeepCopy>)
  - [func \(in \*ImageSpec\) DeepCopyInto\(out \*ImageSpec\)](<#ImageSpec.DeepCopyInto>)
- [type ImageStatus](<#ImageStatus>)
  - [func \(in \*ImageStatus\) DeepCopy\(\) \*ImageStatus](<#ImageStatus.DeepCopy>)
  - [func \(in \*ImageStatus\) DeepCopyInto\(out \*ImageStatus\)](<#ImageStatus.DeepCopyInto>)
- [type LocalAuthConfig](<#LocalAuthConfig>)
  - [func \(in \*LocalAuthConfig\) DeepCopy\(\) \*LocalAuthConfig](<#LocalAuthConfig.DeepCopy>)
  - [func \(in \*LocalAuthConfig\) DeepCopyInto\(out \*LocalAuthConfig\)](<#LocalAuthConfig.DeepCopyInto>)
- [type LocalAuthSpec](<#LocalAuthSpec>)
  - [func \(in \*LocalAuthSpec\) DeepCopy\(\) \*LocalAuthSpec](<#LocalAuthSpec.DeepCopy>)
  - [func \(in \*LocalAuthSpec\) DeepCopyInto\(out \*LocalAuthSpec\)](<#LocalAuthSpec.DeepCopyInto>)
- [type MaintenanceConfig](<#MaintenanceConfig>)
  - [func \(in \*MaintenanceConfig\) DeepCopy\(\) \*MaintenanceConfig](<#MaintenanceConfig.DeepCopy>)
  - [func \(in \*MaintenanceConfig\) DeepCopyInto\(out \*MaintenanceConfig\)](<#MaintenanceConfig.DeepCopyInto>)
- [type NamespaceAccessEntry](<#NamespaceAccessEntry>)
  - [func \(in \*NamespaceAccessEntry\) DeepCopy\(\) \*NamespaceAccessEntry](<#NamespaceAccessEntry.DeepCopy>)
  - [func \(in \*NamespaceAccessEntry\) DeepCopyInto\(out \*NamespaceAccessEntry\)](<#NamespaceAccessEntry.DeepCopyInto>)
- [type OIDCConfig](<#OIDCConfig>)
  - [func \(in \*OIDCConfig\) DeepCopy\(\) \*OIDCConfig](<#OIDCConfig.DeepCopy>)
  - [func \(in \*OIDCConfig\) DeepCopyInto\(out \*OIDCConfig\)](<#OIDCConfig.DeepCopyInto>)
- [type PersonalNamespaceConfig](<#PersonalNamespaceConfig>)
  - [func \(in \*PersonalNamespaceConfig\) DeepCopy\(\) \*PersonalNamespaceConfig](<#PersonalNamespaceConfig.DeepCopy>)
  - [func \(in \*PersonalNamespaceConfig\) DeepCopyInto\(out \*PersonalNamespaceConfig\)](<#PersonalNamespaceConfig.DeepCopyInto>)
- [type PlatformConfig](<#PlatformConfig>)
  - [func \(in \*PlatformConfig\) DeepCopy\(\) \*PlatformConfig](<#PlatformConfig.DeepCopy>)
  - [func \(in \*PlatformConfig\) DeepCopyInto\(out \*PlatformConfig\)](<#PlatformConfig.DeepCopyInto>)
  - [func \(in \*PlatformConfig\) DeepCopyObject\(\) runtime.Object](<#PlatformConfig.DeepCopyObject>)
- [type PlatformConfigList](<#PlatformConfigList>)
  - [func \(in \*PlatformConfigList\) DeepCopy\(\) \*PlatformConfigList](<#PlatformConfigList.DeepCopy>)
  - [func \(in \*PlatformConfigList\) DeepCopyInto\(out \*PlatformConfigList\)](<#PlatformConfigList.DeepCopyInto>)
  - [func \(in \*PlatformConfigList\) DeepCopyObject\(\) runtime.Object](<#PlatformConfigList.DeepCopyObject>)
- [type PlatformConfigSpec](<#PlatformConfigSpec>)
  - [func \(in \*PlatformConfigSpec\) DeepCopy\(\) \*PlatformConfigSpec](<#PlatformConfigSpec.DeepCopy>)
  - [func \(in \*PlatformConfigSpec\) DeepCopyInto\(out \*PlatformConfigSpec\)](<#PlatformConfigSpec.DeepCopyInto>)
- [type PlatformConfigStatus](<#PlatformConfigStatus>)
  - [func \(in \*PlatformConfigStatus\) DeepCopy\(\) \*PlatformConfigStatus](<#PlatformConfigStatus.DeepCopy>)
  - [func \(in \*PlatformConfigStatus\) DeepCopyInto\(out \*PlatformConfigStatus\)](<#PlatformConfigStatus.DeepCopyInto>)
- [type PlatformFormConfig](<#PlatformFormConfig>)
  - [func \(in \*PlatformFormConfig\) DeepCopy\(\) \*PlatformFormConfig](<#PlatformFormConfig.DeepCopy>)
  - [func \(in \*PlatformFormConfig\) DeepCopyInto\(out \*PlatformFormConfig\)](<#PlatformFormConfig.DeepCopyInto>)
- [type PlatformFormFieldLock](<#PlatformFormFieldLock>)
  - [func \(in \*PlatformFormFieldLock\) DeepCopy\(\) \*PlatformFormFieldLock](<#PlatformFormFieldLock.DeepCopy>)
  - [func \(in \*PlatformFormFieldLock\) DeepCopyInto\(out \*PlatformFormFieldLock\)](<#PlatformFormFieldLock.DeepCopyInto>)
- [type PodDefault](<#PodDefault>)
  - [func \(in \*PodDefault\) DeepCopy\(\) \*PodDefault](<#PodDefault.DeepCopy>)
  - [func \(in \*PodDefault\) DeepCopyInto\(out \*PodDefault\)](<#PodDefault.DeepCopyInto>)
  - [func \(in \*PodDefault\) DeepCopyObject\(\) runtime.Object](<#PodDefault.DeepCopyObject>)
- [type PodDefaultList](<#PodDefaultList>)
  - [func \(in \*PodDefaultList\) DeepCopy\(\) \*PodDefaultList](<#PodDefaultList.DeepCopy>)
  - [func \(in \*PodDefaultList\) DeepCopyInto\(out \*PodDefaultList\)](<#PodDefaultList.DeepCopyInto>)
  - [func \(in \*PodDefaultList\) DeepCopyObject\(\) runtime.Object](<#PodDefaultList.DeepCopyObject>)
- [type PodDefaultSpec](<#PodDefaultSpec>)
  - [func \(in \*PodDefaultSpec\) DeepCopy\(\) \*PodDefaultSpec](<#PodDefaultSpec.DeepCopy>)
  - [func \(in \*PodDefaultSpec\) DeepCopyInto\(out \*PodDefaultSpec\)](<#PodDefaultSpec.DeepCopyInto>)
- [type PodDefaultStatus](<#PodDefaultStatus>)
  - [func \(in \*PodDefaultStatus\) DeepCopy\(\) \*PodDefaultStatus](<#PodDefaultStatus.DeepCopy>)
  - [func \(in \*PodDefaultStatus\) DeepCopyInto\(out \*PodDefaultStatus\)](<#PodDefaultStatus.DeepCopyInto>)
- [type RegistrationConfig](<#RegistrationConfig>)
  - [func \(in \*RegistrationConfig\) DeepCopy\(\) \*RegistrationConfig](<#RegistrationConfig.DeepCopy>)
  - [func \(in \*RegistrationConfig\) DeepCopyInto\(out \*RegistrationConfig\)](<#RegistrationConfig.DeepCopyInto>)
- [type SecretKeyRef](<#SecretKeyRef>)
  - [func \(in \*SecretKeyRef\) DeepCopy\(\) \*SecretKeyRef](<#SecretKeyRef.DeepCopy>)
  - [func \(in \*SecretKeyRef\) DeepCopyInto\(out \*SecretKeyRef\)](<#SecretKeyRef.DeepCopyInto>)
- [type SessionConfig](<#SessionConfig>)
  - [func \(in \*SessionConfig\) DeepCopy\(\) \*SessionConfig](<#SessionConfig.DeepCopy>)
  - [func \(in \*SessionConfig\) DeepCopyInto\(out \*SessionConfig\)](<#SessionConfig.DeepCopyInto>)
- [type SshKey](<#SshKey>)
  - [func \(in \*SshKey\) DeepCopy\(\) \*SshKey](<#SshKey.DeepCopy>)
  - [func \(in \*SshKey\) DeepCopyInto\(out \*SshKey\)](<#SshKey.DeepCopyInto>)
  - [func \(in \*SshKey\) DeepCopyObject\(\) runtime.Object](<#SshKey.DeepCopyObject>)
- [type SshKeyList](<#SshKeyList>)
  - [func \(in \*SshKeyList\) DeepCopy\(\) \*SshKeyList](<#SshKeyList.DeepCopy>)
  - [func \(in \*SshKeyList\) DeepCopyInto\(out \*SshKeyList\)](<#SshKeyList.DeepCopyInto>)
  - [func \(in \*SshKeyList\) DeepCopyObject\(\) runtime.Object](<#SshKeyList.DeepCopyObject>)
- [type SshKeySpec](<#SshKeySpec>)
  - [func \(in \*SshKeySpec\) DeepCopy\(\) \*SshKeySpec](<#SshKeySpec.DeepCopy>)
  - [func \(in \*SshKeySpec\) DeepCopyInto\(out \*SshKeySpec\)](<#SshKeySpec.DeepCopyInto>)
- [type User](<#User>)
  - [func \(in \*User\) DeepCopy\(\) \*User](<#User.DeepCopy>)
  - [func \(in \*User\) DeepCopyInto\(out \*User\)](<#User.DeepCopyInto>)
  - [func \(in \*User\) DeepCopyObject\(\) runtime.Object](<#User.DeepCopyObject>)
- [type UserList](<#UserList>)
  - [func \(in \*UserList\) DeepCopy\(\) \*UserList](<#UserList.DeepCopy>)
  - [func \(in \*UserList\) DeepCopyInto\(out \*UserList\)](<#UserList.DeepCopyInto>)
  - [func \(in \*UserList\) DeepCopyObject\(\) runtime.Object](<#UserList.DeepCopyObject>)
- [type UserRole](<#UserRole>)
- [type UserSpec](<#UserSpec>)
  - [func \(in \*UserSpec\) DeepCopy\(\) \*UserSpec](<#UserSpec.DeepCopy>)
  - [func \(in \*UserSpec\) DeepCopyInto\(out \*UserSpec\)](<#UserSpec.DeepCopyInto>)
- [type UserStatus](<#UserStatus>)
  - [func \(in \*UserStatus\) DeepCopy\(\) \*UserStatus](<#UserStatus.DeepCopy>)
  - [func \(in \*UserStatus\) DeepCopyInto\(out \*UserStatus\)](<#UserStatus.DeepCopyInto>)
- [type Workspace](<#Workspace>)
  - [func \(in \*Workspace\) DeepCopy\(\) \*Workspace](<#Workspace.DeepCopy>)
  - [func \(in \*Workspace\) DeepCopyInto\(out \*Workspace\)](<#Workspace.DeepCopyInto>)
  - [func \(in \*Workspace\) DeepCopyObject\(\) runtime.Object](<#Workspace.DeepCopyObject>)
- [type WorkspaceCondition](<#WorkspaceCondition>)
  - [func \(in \*WorkspaceCondition\) DeepCopy\(\) \*WorkspaceCondition](<#WorkspaceCondition.DeepCopy>)
  - [func \(in \*WorkspaceCondition\) DeepCopyInto\(out \*WorkspaceCondition\)](<#WorkspaceCondition.DeepCopyInto>)
- [type WorkspaceList](<#WorkspaceList>)
  - [func \(in \*WorkspaceList\) DeepCopy\(\) \*WorkspaceList](<#WorkspaceList.DeepCopy>)
  - [func \(in \*WorkspaceList\) DeepCopyInto\(out \*WorkspaceList\)](<#WorkspaceList.DeepCopyInto>)
  - [func \(in \*WorkspaceList\) DeepCopyObject\(\) runtime.Object](<#WorkspaceList.DeepCopyObject>)
- [type WorkspaceSpec](<#WorkspaceSpec>)
  - [func \(in \*WorkspaceSpec\) DeepCopy\(\) \*WorkspaceSpec](<#WorkspaceSpec.DeepCopy>)
  - [func \(in \*WorkspaceSpec\) DeepCopyInto\(out \*WorkspaceSpec\)](<#WorkspaceSpec.DeepCopyInto>)
- [type WorkspaceStatus](<#WorkspaceStatus>)
  - [func \(in \*WorkspaceStatus\) DeepCopy\(\) \*WorkspaceStatus](<#WorkspaceStatus.DeepCopy>)
  - [func \(in \*WorkspaceStatus\) DeepCopyInto\(out \*WorkspaceStatus\)](<#WorkspaceStatus.DeepCopyInto>)
- [type WorkspaceTemplateSpec](<#WorkspaceTemplateSpec>)
  - [func \(in \*WorkspaceTemplateSpec\) DeepCopy\(\) \*WorkspaceTemplateSpec](<#WorkspaceTemplateSpec.DeepCopy>)
  - [func \(in \*WorkspaceTemplateSpec\) DeepCopyInto\(out \*WorkspaceTemplateSpec\)](<#WorkspaceTemplateSpec.DeepCopyInto>)


## Variables

<a name="GroupVersion"></a>

```go
var (
    // GroupVersion is group version used to register these objects.
    GroupVersion = schema.GroupVersion{Group: "kubeworkspaces.io", Version: "v1alpha1"}

    // SchemeBuilder is used to add go types to the GroupVersionKind scheme.
    SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

    // AddToScheme adds the types in this group-version to the given scheme.
    AddToScheme = SchemeBuilder.AddToScheme
)
```

<a name="AuthConfig"></a>
## type [AuthConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L206-L212>)

AuthConfig is the Schema for the authconfigs API. It defines the authentication and authorization configuration for kube\-workspaces. Typically only one instance named "default" should exist.

```go
type AuthConfig struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   AuthConfigSpec   `json:"spec,omitempty"`
    Status AuthConfigStatus `json:"status,omitempty"`
}
```

<a name="AuthConfig.DeepCopy"></a>
### func \(\*AuthConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L39>)

```go
func (in *AuthConfig) DeepCopy() *AuthConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthConfig.

<a name="AuthConfig.DeepCopyInto"></a>
### func \(\*AuthConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L30>)

```go
func (in *AuthConfig) DeepCopyInto(out *AuthConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AuthConfig.DeepCopyObject"></a>
### func \(\*AuthConfig\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L49>)

```go
func (in *AuthConfig) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="AuthConfigList"></a>
## type [AuthConfigList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L217-L221>)

AuthConfigList contains a list of AuthConfig.

```go
type AuthConfigList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []AuthConfig `json:"items"`
}
```

<a name="AuthConfigList.DeepCopy"></a>
### func \(\*AuthConfigList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L71>)

```go
func (in *AuthConfigList) DeepCopy() *AuthConfigList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthConfigList.

<a name="AuthConfigList.DeepCopyInto"></a>
### func \(\*AuthConfigList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L57>)

```go
func (in *AuthConfigList) DeepCopyInto(out *AuthConfigList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AuthConfigList.DeepCopyObject"></a>
### func \(\*AuthConfigList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L81>)

```go
func (in *AuthConfigList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="AuthConfigSpec"></a>
## type [AuthConfigSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L151-L178>)

AuthConfigSpec defines the desired state of AuthConfig.

```go
type AuthConfigSpec struct {
    // Enabled is the master switch for authentication. When false, the system operates without auth.
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // OIDC contains the OIDC provider configuration.
    // +optional
    OIDC *OIDCConfig `json:"oidc,omitempty"`
    // Session contains session/token configuration.
    // +optional
    Session *SessionConfig `json:"session,omitempty"`
    // PersonalNamespaces configures personal namespace behavior.
    // +optional
    PersonalNamespaces *PersonalNamespaceConfig `json:"personalNamespaces,omitempty"`
    // Registration configures user registration/provisioning behavior.
    // +optional
    Registration *RegistrationConfig `json:"registration,omitempty"`
    // Authorization configures authorization behavior.
    // +optional
    Authorization *AuthorizationConfig `json:"authorization,omitempty"`
    // AdminEmails is a list of email addresses that are always granted admin role.
    // Used for bootstrapping admin access.
    // +optional
    AdminEmails []string `json:"adminEmails,omitempty"`
    // LocalAuth configures local username/password authentication. It may be
    // enabled independently of, or alongside, OIDC.
    // +optional
    LocalAuth *LocalAuthConfig `json:"localAuth,omitempty"`
}
```

<a name="AuthConfigSpec.DeepCopy"></a>
### func \(\*AuthConfigSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L129>)

```go
func (in *AuthConfigSpec) DeepCopy() *AuthConfigSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthConfigSpec.

<a name="AuthConfigSpec.DeepCopyInto"></a>
### func \(\*AuthConfigSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L89>)

```go
func (in *AuthConfigSpec) DeepCopyInto(out *AuthConfigSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AuthConfigStatus"></a>
## type [AuthConfigStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L181-L194>)

AuthConfigStatus defines the observed state of AuthConfig.

```go
type AuthConfigStatus struct {
    // Enabled reflects whether auth is currently active.
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // IssuerReachable indicates whether the OIDC issuer is reachable.
    // +optional
    IssuerReachable bool `json:"issuerReachable,omitempty"`
    // LastVerified is when the OIDC issuer was last verified.
    // +optional
    LastVerified *metav1.Time `json:"lastVerified,omitempty"`
    // Conditions represent the latest available observations.
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

<a name="AuthConfigStatus.DeepCopy"></a>
### func \(\*AuthConfigStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L155>)

```go
func (in *AuthConfigStatus) DeepCopy() *AuthConfigStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthConfigStatus.

<a name="AuthConfigStatus.DeepCopyInto"></a>
### func \(\*AuthConfigStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L139>)

```go
func (in *AuthConfigStatus) DeepCopyInto(out *AuthConfigStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AuthorizationConfig"></a>
## type [AuthorizationConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L117-L124>)

AuthorizationConfig defines authorization behavior.

```go
type AuthorizationConfig struct {
    // RestrictNamespaceAccess when true, non-admin users can only access namespaces
    // explicitly assigned to them (via User CR namespaceAccess + personal namespace).
    // When false (default), all authenticated users can see all namespaces.
    // Admins always have access to everything regardless of this setting.
    // +optional
    RestrictNamespaceAccess bool `json:"restrictNamespaceAccess,omitempty"`
}
```

<a name="AuthorizationConfig.DeepCopy"></a>
### func \(\*AuthorizationConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L170>)

```go
func (in *AuthorizationConfig) DeepCopy() *AuthorizationConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthorizationConfig.

<a name="AuthorizationConfig.DeepCopyInto"></a>
### func \(\*AuthorizationConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L165>)

```go
func (in *AuthorizationConfig) DeepCopyInto(out *AuthorizationConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="BootstrapAdminConfig"></a>
## type [BootstrapAdminConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L127-L136>)

BootstrapAdminConfig defines auto\-creation of the default local admin user.

```go
type BootstrapAdminConfig struct {
    // Email is the identifier used for the auto-created admin user.
    // +optional
    // +kubebuilder:default="admin@local"
    Email string `json:"email,omitempty"`
    // Skip disables auto-creation of the bootstrap admin user, e.g. when an
    // admin user has already been provisioned manually.
    // +optional
    Skip bool `json:"skip,omitempty"`
}
```

<a name="BootstrapAdminConfig.DeepCopy"></a>
### func \(\*BootstrapAdminConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L185>)

```go
func (in *BootstrapAdminConfig) DeepCopy() *BootstrapAdminConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BootstrapAdminConfig.

<a name="BootstrapAdminConfig.DeepCopyInto"></a>
### func \(\*BootstrapAdminConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L180>)

```go
func (in *BootstrapAdminConfig) DeepCopyInto(out *BootstrapAdminConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="Image"></a>
## type [Image](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L263-L269>)

Image is the Schema for the images API. It describes an available workspace image with its default configuration.

```go
type Image struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   ImageSpec   `json:"spec,omitempty"`
    Status ImageStatus `json:"status,omitempty"`
}
```

<a name="Image.DeepCopy"></a>
### func \(\*Image\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L204>)

```go
func (in *Image) DeepCopy() *Image
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Image.

<a name="Image.DeepCopyInto"></a>
### func \(\*Image\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L195>)

```go
func (in *Image) DeepCopyInto(out *Image)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="Image.DeepCopyObject"></a>
### func \(\*Image\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L214>)

```go
func (in *Image) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="ImageCredentials"></a>
## type [ImageCredentials](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L182-L189>)

ImageCredentials represents default login credentials for a workspace image.

```go
type ImageCredentials struct {
    // Username is the default username.
    // +optional
    Username string `json:"username,omitempty"`
    // Password is the default password.
    // +optional
    Password string `json:"password,omitempty"`
}
```

<a name="ImageCredentials.DeepCopy"></a>
### func \(\*ImageCredentials\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L227>)

```go
func (in *ImageCredentials) DeepCopy() *ImageCredentials
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageCredentials.

<a name="ImageCredentials.DeepCopyInto"></a>
### func \(\*ImageCredentials\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L222>)

```go
func (in *ImageCredentials) DeepCopyInto(out *ImageCredentials)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageEnvVar"></a>
## type [ImageEnvVar](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L174-L179>)

ImageEnvVar represents an environment variable with optional placeholder support.

```go
type ImageEnvVar struct {
    // Name of the environment variable.
    Name string `json:"name"`
    // Value supports {{namespace}} and {{name}} placeholders.
    Value string `json:"value"`
}
```

<a name="ImageEnvVar.DeepCopy"></a>
### func \(\*ImageEnvVar\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L242>)

```go
func (in *ImageEnvVar) DeepCopy() *ImageEnvVar
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageEnvVar.

<a name="ImageEnvVar.DeepCopyInto"></a>
### func \(\*ImageEnvVar\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L237>)

```go
func (in *ImageEnvVar) DeepCopyInto(out *ImageEnvVar)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageLink"></a>
## type [ImageLink](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L166-L171>)

ImageLink represents a named URL link for an image.

```go
type ImageLink struct {
    // Title is the display label for the link.
    Title string `json:"title"`
    // URL is the link target.
    URL string `json:"url"`
}
```

<a name="ImageLink.DeepCopy"></a>
### func \(\*ImageLink\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L257>)

```go
func (in *ImageLink) DeepCopy() *ImageLink
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageLink.

<a name="ImageLink.DeepCopyInto"></a>
### func \(\*ImageLink\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L252>)

```go
func (in *ImageLink) DeepCopyInto(out *ImageLink)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageList"></a>
## type [ImageList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L274-L278>)

ImageList contains a list of Image.

```go
type ImageList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []Image `json:"items"`
}
```

<a name="ImageList.DeepCopy"></a>
### func \(\*ImageList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L281>)

```go
func (in *ImageList) DeepCopy() *ImageList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageList.

<a name="ImageList.DeepCopyInto"></a>
### func \(\*ImageList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L267>)

```go
func (in *ImageList) DeepCopyInto(out *ImageList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageList.DeepCopyObject"></a>
### func \(\*ImageList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L291>)

```go
func (in *ImageList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="ImagePort"></a>
## type [ImagePort](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L192-L200>)

ImagePort represents an additional container port to expose.

```go
type ImagePort struct {
    // Name of the port (used as Service port name).
    Name string `json:"name"`
    // Port number to expose.
    Port int32 `json:"port"`
    // Protocol (defaults to TCP).
    // +optional
    Protocol string `json:"protocol,omitempty"`
}
```

<a name="ImagePort.DeepCopy"></a>
### func \(\*ImagePort\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L304>)

```go
func (in *ImagePort) DeepCopy() *ImagePort
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImagePort.

<a name="ImagePort.DeepCopyInto"></a>
### func \(\*ImagePort\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L299>)

```go
func (in *ImagePort) DeepCopyInto(out *ImagePort)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageProxyConfig"></a>
## type [ImageProxyConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L203-L244>)

ImageProxyConfig describes how the reverse proxy should behave for this image.

```go
type ImageProxyConfig struct {
    // NeedsNoopSW: serve a no-op ServiceWorker at /sw.js to prevent SW registration errors.
    // +optional
    NeedsNoopSW bool `json:"needsNoopSW,omitempty"`
    // WebSocketPaths: paths that use WebSocket (informational — all paths support WS transparently).
    // +optional
    WebSocketPaths []string `json:"websocketPaths,omitempty"`
    // RewriteHostAbsolutePaths: rewrite requests with absolute paths that escape the proxy
    // prefix by using the Referer header to determine the target workspace.
    // +optional
    RewriteHostAbsolutePaths bool `json:"rewriteHostAbsolutePaths,omitempty"`
    // CustomRequestHeaders: additional headers to inject into proxied requests.
    // +optional
    CustomRequestHeaders map[string]string `json:"customRequestHeaders,omitempty"`
    // InjectBaseTag: inject a <base> tag into HTML responses.
    // +optional
    InjectBaseTag bool `json:"injectBaseTag,omitempty"`
    // Scheme: URL scheme the proxy uses to reach the workspace backend.
    // Defaults to "http" when empty.
    // +kubebuilder:validation:Enum=http;https
    // +optional
    Scheme string `json:"scheme,omitempty"`
    // TLSSkipVerify: when connecting over HTTPS, do not verify the backend's
    // certificate. Required for workspaces serving self-signed certificates.
    // +optional
    TLSSkipVerify bool `json:"tlsSkipVerify,omitempty"`
    // TLSInsecure: Deprecated: this conflated scheme selection with certificate
    // verification, making "HTTPS with a valid CA" impossible to express. Use
    // scheme: https plus tlsSkipVerify instead. Still honoured as a fallback when
    // scheme is unset: it implies both HTTPS and skip-verify.
    // +optional
    TLSInsecure bool `json:"tlsInsecure,omitempty"`
    // PreservePathPrefix: forward the full proxy path (including /proxy/{ns}/{name}) to the
    // workspace pod instead of stripping it. Required for apps that are configured with a
    // base URL matching the proxy prefix (e.g. filebrowser --baseurl, JupyterLab --base-url).
    // +optional
    PreservePathPrefix bool `json:"preservePathPrefix,omitempty"`
    // AudioPort: backend port for audio WebSocket connections. When set, the proxy routes
    // requests matching /audio/ to this port instead of the default workspace port.
    // +optional
    AudioPort int32 `json:"audioPort,omitempty"`
}
```

<a name="ImageProxyConfig.DeepCopy"></a>
### func \(\*ImageProxyConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L331>)

```go
func (in *ImageProxyConfig) DeepCopy() *ImageProxyConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageProxyConfig.

<a name="ImageProxyConfig.DeepCopyInto"></a>
### func \(\*ImageProxyConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L314>)

```go
func (in *ImageProxyConfig) DeepCopyInto(out *ImageProxyConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageSpec"></a>
## type [ImageSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L25-L163>)

ImageSpec defines the desired state of Image.

```go
type ImageSpec struct {
    // Container image reference (e.g. "codercom/code-server:latest").
    Image string `json:"image"`
    // Display name (e.g. "Code Server (VS Code)").
    // +optional
    DisplayName string `json:"displayName,omitempty"`
    // Description of the image.
    // +optional
    Description string `json:"description,omitempty"`
    // Category groups this image for UI display (e.g. "Desktop", "IDE", "Tool", "Game").
    // +optional
    Category string `json:"category,omitempty"`
    // Tags are optional labels for filtering/searching images.
    // +optional
    Tags []string `json:"tags,omitempty"`
    // Default container port.
    DefaultPort int32 `json:"defaultPort"`
    // Default URL path for connecting (e.g. "/vnc.html?resize=remote").
    // +optional
    DefaultPath string `json:"defaultPath,omitempty"`
    // Icon identifier (e.g. "vscode", "desktop").
    // +optional
    Icon string `json:"icon,omitempty"`
    // Default command-line args injected at workspace creation.
    // +optional
    DefaultArgs []string `json:"defaultArgs,omitempty"`
    // Default environment variables injected at workspace creation.
    // Supports {{namespace}} and {{name}} placeholders.
    // +optional
    DefaultEnv []ImageEnvVar `json:"defaultEnv,omitempty"`
    // DefaultCredentials are the default login credentials for this image.
    // +optional
    DefaultCredentials *ImageCredentials `json:"defaultCredentials,omitempty"`
    // Privileged indicates that containers using this image should run in privileged mode.
    // +optional
    Privileged bool `json:"privileged,omitempty"`
    // HomepageURL is the project homepage or documentation URL.
    // +optional
    HomepageURL string `json:"homepageURL,omitempty"`
    // SourceURL is the source code repository URL.
    // +optional
    SourceURL string `json:"sourceURL,omitempty"`
    // ImageHomepageURL is the container image registry page (e.g. Docker Hub).
    // +optional
    ImageHomepageURL string `json:"imageHomepageURL,omitempty"`
    // DefaultUser is the default user for this image.
    // +optional
    DefaultUser string `json:"defaultUser,omitempty"`
    // DefaultPassword is the default password for DefaultUser. Only set when the
    // image has a known default password for this user; leave empty/unset when
    // there is no known default (e.g. the guest uses no password).
    // +optional
    DefaultPassword string `json:"defaultPassword,omitempty"`
    // DefaultCloudInit indicates the image has cloud-init baked in. When true,
    // user-data (e.g. a user/password from DefaultUser/DefaultPassword) can be
    // seeded into the guest at first boot.
    // +optional
    DefaultCloudInit bool `json:"defaultCloudInit,omitempty"`
    // DefaultUserData is reserved user-data for the guest (cloud-init). Empty by
    // default; later used to seed first-boot configuration when DefaultCloudInit
    // is true. Not yet consumed by the controller.
    // +optional
    DefaultUserData string `json:"defaultUserData,omitempty"`
    // DefaultHomedir is the default home directory for the default user.
    // +optional
    DefaultHomedir string `json:"defaultHomedir,omitempty"`
    // DefaultShell is the default shell for exec/console sessions (e.g. "/bin/bash").
    // Falls back to /bin/bash then /bin/sh if not specified.
    // +optional
    DefaultShell string `json:"defaultShell,omitempty"`
    // Links are additional relevant URLs for this image.
    // +optional
    Links []ImageLink `json:"links,omitempty"`
    // Proxy configuration for this image.
    // +optional
    ProxyConfig *ImageProxyConfig `json:"proxyConfig,omitempty"`
    // DefaultUID is the UID that the main container runs as. When set, the controller
    // will configure pod securityContext with runAsUser and fsGroup set to this value,
    // ensuring mounted volumes are accessible to the container process.
    // +optional
    DefaultUID *int64 `json:"defaultUID,omitempty"`
    // DefaultInitContainers are init containers injected into workspace pods at creation time.
    // Useful for volume permission fixups (e.g. chown to match the container's UID).
    // Supports {{namespace}}, {{name}}, and {{uid}} placeholders in args and env values.
    // +optional
    DefaultInitContainers []corev1.Container `json:"defaultInitContainers,omitempty"`
    // AdditionalPorts lists extra container ports to expose beyond the primary defaultPort.
    // These are added to the workspace pod and exposed via the Service.
    // +optional
    AdditionalPorts []ImagePort `json:"additionalPorts,omitempty"`
    // DefaultSharedMemory indicates that workspaces created from this image should
    // automatically mount /dev/shm as an emptyDir with medium=Memory. Required for
    // images that use shared memory for video encoding (e.g. Selkies/KasmVNC streaming,
    // Chrome/Chromium, ML frameworks).
    // +optional
    DefaultSharedMemory bool `json:"defaultSharedMemory,omitempty"`
    // WorkspaceTypes lists the workspace types this image can be used with
    // ("container", "vm", "scratch"). When empty, the image is offered for
    // "container" workspaces only. VM images must be containerDisk images
    // containing a bootable guest disk.
    // +optional
    WorkspaceTypes []string `json:"workspaceTypes,omitempty"`
    // PersistentRootDisk indicates the VM root disk should be a DataVolume
    // backing-persistent PVC imported from the container disk image (via CDI)
    // rather than an ephemeral containerDisk. Requires a storage class that CDI
    // can provision. Ignored for non-vm workspaces.
    // +optional
    PersistentRootDisk bool `json:"persistentRootDisk,omitempty"`
    // PersistentRootDiskSize is the requested root PVC size when
    // PersistentRootDisk is true (e.g. "10Gi"). Defaults to "10Gi" when empty.
    // +optional
    PersistentRootDiskSize string `json:"persistentRootDiskSize,omitempty"`
    // MemoryLimit overrides the VM domain memory (guest RAM) for vm workspaces
    // (e.g. "4Gi"). Useful for desktop images that need more memory than the
    // container-default memory requests/limits. Empty means use the container's
    // resources as-is.
    // +optional
    MemoryLimit string `json:"memoryLimit,omitempty"`
    // MemoryRequest overrides the virt-launcher pod memory request and limit for
    // vm workspaces (e.g. "5Gi"). Use together with MemoryLimit to decouple the
    // pod allocation from the guest RAM: the guest gets MemoryLimit while the pod
    // is granted extra headroom for qemu overhead (TCG translation buffers, page
    // cache, virt-launcher), preventing OOM-kills when limits would otherwise sit
    // at exactly MemoryLimit plus KubeVirt's minimal overhead. Requires
    // MemoryRequest >= MemoryLimit. Empty keeps the pod request/limit equal to
    // MemoryLimit (or the container defaults when MemoryLimit is empty).
    // +optional
    MemoryRequest string `json:"memoryRequest,omitempty"`
    // VideoDevice overrides the KubeVirt domain video device type for vm
    // workspaces (sets domain.devices.video.type). "virtio" attaches the
    // virtio-gpu paravirtual display (recommended for modern desktop guests
    // with virtio graphics drivers); other valid values are "vga", "bochs",
    // "cirrus" and "ramfb". Empty uses KubeVirt's default auto-attach (VGA for
    // BIOS, bochs for EFI) and leaves domain.devices.video unset. Ignored for
    // non-vm workspaces.
    // +kubebuilder:validation:Enum=virtio;vga;bochs;cirrus;ramfb
    // +optional
    VideoDevice string `json:"videoDevice,omitempty"`
}
```

<a name="ImageSpec.DeepCopy"></a>
### func \(\*ImageSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L398>)

```go
func (in *ImageSpec) DeepCopy() *ImageSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSpec.

<a name="ImageSpec.DeepCopyInto"></a>
### func \(\*ImageSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L341>)

```go
func (in *ImageSpec) DeepCopyInto(out *ImageSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="ImageStatus"></a>
## type [ImageStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/image_types.go#L247-L251>)

ImageStatus defines the observed state of Image.

```go
type ImageStatus struct {
    // Conditions is an array of current conditions.
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

<a name="ImageStatus.DeepCopy"></a>
### func \(\*ImageStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L420>)

```go
func (in *ImageStatus) DeepCopy() *ImageStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageStatus.

<a name="ImageStatus.DeepCopyInto"></a>
### func \(\*ImageStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L408>)

```go
func (in *ImageStatus) DeepCopyInto(out *ImageStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="LocalAuthConfig"></a>
## type [LocalAuthConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L140-L148>)

LocalAuthConfig defines local \(username/password\) authentication behavior. LocalAuth may be enabled independently of, or alongside, OIDC.

```go
type LocalAuthConfig struct {
    // Enabled controls whether local username/password authentication is available.
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // BootstrapAdmin configures auto-creation of a default admin user when local
    // auth is first enabled.
    // +optional
    BootstrapAdmin *BootstrapAdminConfig `json:"bootstrapAdmin,omitempty"`
}
```

<a name="LocalAuthConfig.DeepCopy"></a>
### func \(\*LocalAuthConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L440>)

```go
func (in *LocalAuthConfig) DeepCopy() *LocalAuthConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalAuthConfig.

<a name="LocalAuthConfig.DeepCopyInto"></a>
### func \(\*LocalAuthConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L430>)

```go
func (in *LocalAuthConfig) DeepCopyInto(out *LocalAuthConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="LocalAuthSpec"></a>
## type [LocalAuthSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L43-L56>)

LocalAuthSpec defines local \(username/password\) authentication for a user.

```go
type LocalAuthSpec struct {
    // Enabled controls whether this user may authenticate with a local password,
    // in addition to any other configured authentication method (e.g. OIDC).
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // PasswordSecretRef references the Secret and key holding the bcrypt password
    // hash for this user (key is conventionally "passwordHash").
    // +optional
    PasswordSecretRef SecretKeyRef `json:"passwordSecretRef,omitempty"`
    // MustChangePassword indicates the user must set a new password before
    // continuing to use the system. Set on creation/reset, cleared on change.
    // +optional
    MustChangePassword bool `json:"mustChangePassword,omitempty"`
}
```

<a name="LocalAuthSpec.DeepCopy"></a>
### func \(\*LocalAuthSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L456>)

```go
func (in *LocalAuthSpec) DeepCopy() *LocalAuthSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalAuthSpec.

<a name="LocalAuthSpec.DeepCopyInto"></a>
### func \(\*LocalAuthSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L450>)

```go
func (in *LocalAuthSpec) DeepCopyInto(out *LocalAuthSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="MaintenanceConfig"></a>
## type [MaintenanceConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L24-L33>)

MaintenanceConfig defines maintenance mode settings.

```go
type MaintenanceConfig struct {
    // Enabled controls whether maintenance mode is active.
    // When true, non-admin users see the maintenance page and cannot create/manage workspaces.
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // Message is an optional message displayed to users during maintenance.
    // Supports plain text. If empty, a default message is shown.
    // +optional
    Message string `json:"message,omitempty"`
}
```

<a name="MaintenanceConfig.DeepCopy"></a>
### func \(\*MaintenanceConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L471>)

```go
func (in *MaintenanceConfig) DeepCopy() *MaintenanceConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MaintenanceConfig.

<a name="MaintenanceConfig.DeepCopyInto"></a>
### func \(\*MaintenanceConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L466>)

```go
func (in *MaintenanceConfig) DeepCopyInto(out *MaintenanceConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="NamespaceAccessEntry"></a>
## type [NamespaceAccessEntry](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L34-L40>)

NamespaceAccessEntry defines access to an additional shared namespace.

```go
type NamespaceAccessEntry struct {
    // Namespace is the target namespace name.
    Namespace string `json:"namespace"`
    // Role is the access level in this namespace.
    // +kubebuilder:validation:Enum=admin;editor;viewer
    Role UserRole `json:"role"`
}
```

<a name="NamespaceAccessEntry.DeepCopy"></a>
### func \(\*NamespaceAccessEntry\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L486>)

```go
func (in *NamespaceAccessEntry) DeepCopy() *NamespaceAccessEntry
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespaceAccessEntry.

<a name="NamespaceAccessEntry.DeepCopyInto"></a>
### func \(\*NamespaceAccessEntry\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L481>)

```go
func (in *NamespaceAccessEntry) DeepCopyInto(out *NamespaceAccessEntry)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="OIDCConfig"></a>
## type [OIDCConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L32-L54>)

OIDCConfig defines the OIDC provider configuration.

```go
type OIDCConfig struct {
    // IssuerURL is the OIDC issuer URL (e.g. https://dex.example.com).
    // +kubebuilder:validation:Required
    IssuerURL string `json:"issuerURL"`
    // ClientID is the OAuth2 client ID.
    // +kubebuilder:validation:Required
    ClientID string `json:"clientID"`
    // ClientSecret is a reference to the secret containing the OAuth2 client secret.
    // +kubebuilder:validation:Required
    ClientSecret SecretKeyRef `json:"clientSecret"`
    // Scopes are the OIDC scopes to request.
    // +optional
    // +kubebuilder:default={"openid","email","profile","groups"}
    Scopes []string `json:"scopes,omitempty"`
    // UsernameClaim is the JWT claim to use as the username.
    // +optional
    // +kubebuilder:default=email
    UsernameClaim string `json:"usernameClaim,omitempty"`
    // GroupsClaim is the JWT claim to use for group membership.
    // +optional
    // +kubebuilder:default=groups
    GroupsClaim string `json:"groupsClaim,omitempty"`
}
```

<a name="OIDCConfig.DeepCopy"></a>
### func \(\*OIDCConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L507>)

```go
func (in *OIDCConfig) DeepCopy() *OIDCConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCConfig.

<a name="OIDCConfig.DeepCopyInto"></a>
### func \(\*OIDCConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L496>)

```go
func (in *OIDCConfig) DeepCopyInto(out *OIDCConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PersonalNamespaceConfig"></a>
## type [PersonalNamespaceConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L72-L89>)

PersonalNamespaceConfig defines personal namespace behavior.

```go
type PersonalNamespaceConfig struct {
    // Enabled controls whether personal namespaces are created for users.
    // +optional
    Enabled bool `json:"enabled,omitempty"`
    // Template is the namespace name template. Supports {{username}} placeholder.
    // +optional
    // +kubebuilder:default="{{username}}"
    Template string `json:"template,omitempty"`
    // Labels are applied to created personal namespaces.
    // +optional
    Labels map[string]string `json:"labels,omitempty"`
    // Annotations are applied to created personal namespaces.
    // +optional
    Annotations map[string]string `json:"annotations,omitempty"`
    // ResourceQuota defines optional resource limits for personal namespaces.
    // +optional
    ResourceQuota map[string]string `json:"resourceQuota,omitempty"`
}
```

<a name="PersonalNamespaceConfig.DeepCopy"></a>
### func \(\*PersonalNamespaceConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L543>)

```go
func (in *PersonalNamespaceConfig) DeepCopy() *PersonalNamespaceConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PersonalNamespaceConfig.

<a name="PersonalNamespaceConfig.DeepCopyInto"></a>
### func \(\*PersonalNamespaceConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L517>)

```go
func (in *PersonalNamespaceConfig) DeepCopyInto(out *PersonalNamespaceConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformConfig"></a>
## type [PlatformConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L85-L91>)

PlatformConfig is the Schema for the platformconfigs API. It defines platform\-wide configuration for kube\-workspaces that is not related to authentication. Typically only one instance named "default" should exist.

```go
type PlatformConfig struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   PlatformConfigSpec   `json:"spec,omitempty"`
    Status PlatformConfigStatus `json:"status,omitempty"`
}
```

<a name="PlatformConfig.DeepCopy"></a>
### func \(\*PlatformConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L562>)

```go
func (in *PlatformConfig) DeepCopy() *PlatformConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformConfig.

<a name="PlatformConfig.DeepCopyInto"></a>
### func \(\*PlatformConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L553>)

```go
func (in *PlatformConfig) DeepCopyInto(out *PlatformConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformConfig.DeepCopyObject"></a>
### func \(\*PlatformConfig\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L572>)

```go
func (in *PlatformConfig) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="PlatformConfigList"></a>
## type [PlatformConfigList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L96-L100>)

PlatformConfigList contains a list of PlatformConfig.

```go
type PlatformConfigList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []PlatformConfig `json:"items"`
}
```

<a name="PlatformConfigList.DeepCopy"></a>
### func \(\*PlatformConfigList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L594>)

```go
func (in *PlatformConfigList) DeepCopy() *PlatformConfigList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformConfigList.

<a name="PlatformConfigList.DeepCopyInto"></a>
### func \(\*PlatformConfigList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L580>)

```go
func (in *PlatformConfigList) DeepCopyInto(out *PlatformConfigList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformConfigList.DeepCopyObject"></a>
### func \(\*PlatformConfigList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L604>)

```go
func (in *PlatformConfigList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="PlatformConfigSpec"></a>
## type [PlatformConfigSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L57-L64>)

PlatformConfigSpec defines the desired state of PlatformConfig.

```go
type PlatformConfigSpec struct {
    // Maintenance configures maintenance mode for the platform.
    // +optional
    Maintenance *MaintenanceConfig `json:"maintenance,omitempty"`
    // Form configures workspace creation form behavior including field locking.
    // +optional
    Form *PlatformFormConfig `json:"form,omitempty"`
}
```

<a name="PlatformConfigSpec.DeepCopy"></a>
### func \(\*PlatformConfigSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L627>)

```go
func (in *PlatformConfigSpec) DeepCopy() *PlatformConfigSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformConfigSpec.

<a name="PlatformConfigSpec.DeepCopyInto"></a>
### func \(\*PlatformConfigSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L612>)

```go
func (in *PlatformConfigSpec) DeepCopyInto(out *PlatformConfigSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformConfigStatus"></a>
## type [PlatformConfigStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L67-L74>)

PlatformConfigStatus defines the observed state of PlatformConfig.

```go
type PlatformConfigStatus struct {
    // MaintenanceActive reflects whether maintenance mode is currently active.
    // +optional
    MaintenanceActive bool `json:"maintenanceActive,omitempty"`
    // Conditions represent the latest available observations.
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

<a name="PlatformConfigStatus.DeepCopy"></a>
### func \(\*PlatformConfigStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L649>)

```go
func (in *PlatformConfigStatus) DeepCopy() *PlatformConfigStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformConfigStatus.

<a name="PlatformConfigStatus.DeepCopyInto"></a>
### func \(\*PlatformConfigStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L637>)

```go
func (in *PlatformConfigStatus) DeepCopyInto(out *PlatformConfigStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformFormConfig"></a>
## type [PlatformFormConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L49-L54>)

PlatformFormConfig defines workspace creation form behavior.

```go
type PlatformFormConfig struct {
    // LockedFields lists form fields that non-admin users cannot modify.
    // Admins can always override locked fields.
    // +optional
    LockedFields []PlatformFormFieldLock `json:"lockedFields,omitempty"`
}
```

<a name="PlatformFormConfig.DeepCopy"></a>
### func \(\*PlatformFormConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L669>)

```go
func (in *PlatformFormConfig) DeepCopy() *PlatformFormConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformFormConfig.

<a name="PlatformFormConfig.DeepCopyInto"></a>
### func \(\*PlatformFormConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L659>)

```go
func (in *PlatformFormConfig) DeepCopyInto(out *PlatformFormConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PlatformFormFieldLock"></a>
## type [PlatformFormFieldLock](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/platformconfig_types.go#L36-L46>)

PlatformFormFieldLock defines a locked form field with its enforced value.

```go
type PlatformFormFieldLock struct {
    // Field is the name of the form field to lock (e.g. "image_pull_policy", "gpu", "shared_memory", "cpu_limit", "memory_limit").
    Field string `json:"field"`
    // Value is the enforced value for the field. For boolean fields use "true"/"false".
    // For select fields use the option value. Empty string means use the default.
    // +optional
    Value string `json:"value,omitempty"`
    // Message is an optional hint displayed to users explaining why the field is locked.
    // +optional
    Message string `json:"message,omitempty"`
}
```

<a name="PlatformFormFieldLock.DeepCopy"></a>
### func \(\*PlatformFormFieldLock\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L684>)

```go
func (in *PlatformFormFieldLock) DeepCopy() *PlatformFormFieldLock
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformFormFieldLock.

<a name="PlatformFormFieldLock.DeepCopyInto"></a>
### func \(\*PlatformFormFieldLock\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L679>)

```go
func (in *PlatformFormFieldLock) DeepCopyInto(out *PlatformFormFieldLock)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PodDefault"></a>
## type [PodDefault](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/poddefault_types.go#L68-L74>)

PodDefault is the Schema for the poddefaults API. It defines configuration that is automatically injected into matching workspace pods at creation time.

```go
type PodDefault struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   PodDefaultSpec   `json:"spec,omitempty"`
    Status PodDefaultStatus `json:"status,omitempty"`
}
```

<a name="PodDefault.DeepCopy"></a>
### func \(\*PodDefault\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L703>)

```go
func (in *PodDefault) DeepCopy() *PodDefault
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodDefault.

<a name="PodDefault.DeepCopyInto"></a>
### func \(\*PodDefault\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L694>)

```go
func (in *PodDefault) DeepCopyInto(out *PodDefault)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PodDefault.DeepCopyObject"></a>
### func \(\*PodDefault\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L713>)

```go
func (in *PodDefault) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="PodDefaultList"></a>
## type [PodDefaultList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/poddefault_types.go#L79-L83>)

PodDefaultList contains a list of PodDefault.

```go
type PodDefaultList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []PodDefault `json:"items"`
}
```

<a name="PodDefaultList.DeepCopy"></a>
### func \(\*PodDefaultList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L735>)

```go
func (in *PodDefaultList) DeepCopy() *PodDefaultList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodDefaultList.

<a name="PodDefaultList.DeepCopyInto"></a>
### func \(\*PodDefaultList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L721>)

```go
func (in *PodDefaultList) DeepCopyInto(out *PodDefaultList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PodDefaultList.DeepCopyObject"></a>
### func \(\*PodDefaultList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L745>)

```go
func (in *PodDefaultList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="PodDefaultSpec"></a>
## type [PodDefaultSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/poddefault_types.go#L25-L51>)

PodDefaultSpec defines configuration to inject into matching workspace pods.

```go
type PodDefaultSpec struct {
    // Selector is a label selector that determines which workspaces this PodDefault applies to.
    // If empty, applies to all workspaces in the namespace.
    // +optional
    Selector *metav1.LabelSelector `json:"selector,omitempty"`
    // Desc is a human-readable description of what this PodDefault provides.
    // +optional
    Desc string `json:"desc,omitempty"`
    // Env are additional environment variables to inject into workspace containers.
    // +optional
    Env []corev1.EnvVar `json:"env,omitempty"`
    // VolumeMounts are additional volume mounts to inject into workspace containers.
    // +optional
    VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`
    // Volumes are additional volumes to add to the workspace pod.
    // +optional
    Volumes []corev1.Volume `json:"volumes,omitempty"`
    // ServiceAccountName overrides the pod's service account.
    // +optional
    ServiceAccountName string `json:"serviceAccountName,omitempty"`
    // Annotations are additional annotations to add to the workspace pod.
    // +optional
    Annotations map[string]string `json:"annotations,omitempty"`
    // Labels are additional labels to add to the workspace pod.
    // +optional
    Labels map[string]string `json:"labels,omitempty"`
}
```

<a name="PodDefaultSpec.DeepCopy"></a>
### func \(\*PodDefaultSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L798>)

```go
func (in *PodDefaultSpec) DeepCopy() *PodDefaultSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodDefaultSpec.

<a name="PodDefaultSpec.DeepCopyInto"></a>
### func \(\*PodDefaultSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L753>)

```go
func (in *PodDefaultSpec) DeepCopyInto(out *PodDefaultSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="PodDefaultStatus"></a>
## type [PodDefaultStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/poddefault_types.go#L54-L58>)

PodDefaultStatus defines the observed state of PodDefault.

```go
type PodDefaultStatus struct {
    // Conditions is an array of current conditions.
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

<a name="PodDefaultStatus.DeepCopy"></a>
### func \(\*PodDefaultStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L820>)

```go
func (in *PodDefaultStatus) DeepCopy() *PodDefaultStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodDefaultStatus.

<a name="PodDefaultStatus.DeepCopyInto"></a>
### func \(\*PodDefaultStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L808>)

```go
func (in *PodDefaultStatus) DeepCopyInto(out *PodDefaultStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="RegistrationConfig"></a>
## type [RegistrationConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L92-L114>)

RegistrationConfig defines user registration/provisioning behavior.

```go
type RegistrationConfig struct {
    // AutoProvision controls whether User CRs are auto-created on first OIDC login.
    // +optional
    // +kubebuilder:default=true
    AutoProvision bool `json:"autoProvision,omitempty"`
    // DefaultRole is the role assigned to newly provisioned users.
    // +optional
    // +kubebuilder:default=editor
    // +kubebuilder:validation:Enum=admin;editor;viewer
    DefaultRole UserRole `json:"defaultRole,omitempty"`
    // AllowedDomains restricts registration to specific email domains. Empty means allow all.
    // When both AllowedDomains and AllowedEmails are set, either match permits login (OR logic).
    // +optional
    AllowedDomains []string `json:"allowedDomains,omitempty"`
    // AllowedEmails restricts login to specific email addresses. Empty means allow all.
    // Emails in spec.adminEmails always bypass this restriction.
    // When both AllowedDomains and AllowedEmails are set, either match permits login (OR logic).
    // +optional
    AllowedEmails []string `json:"allowedEmails,omitempty"`
    // RequireApproval if true, new users are created as disabled until an admin enables them.
    // +optional
    RequireApproval bool `json:"requireApproval,omitempty"`
}
```

<a name="RegistrationConfig.DeepCopy"></a>
### func \(\*RegistrationConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L845>)

```go
func (in *RegistrationConfig) DeepCopy() *RegistrationConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RegistrationConfig.

<a name="RegistrationConfig.DeepCopyInto"></a>
### func \(\*RegistrationConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L830>)

```go
func (in *RegistrationConfig) DeepCopyInto(out *RegistrationConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="SecretKeyRef"></a>
## type [SecretKeyRef](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L24-L29>)

SecretKeyRef is a reference to a key in a Secret.

```go
type SecretKeyRef struct {
    // Name is the name of the secret.
    Name string `json:"name"`
    // Key is the key within the secret.
    Key string `json:"key"`
}
```

<a name="SecretKeyRef.DeepCopy"></a>
### func \(\*SecretKeyRef\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L860>)

```go
func (in *SecretKeyRef) DeepCopy() *SecretKeyRef
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretKeyRef.

<a name="SecretKeyRef.DeepCopyInto"></a>
### func \(\*SecretKeyRef\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L855>)

```go
func (in *SecretKeyRef) DeepCopyInto(out *SecretKeyRef)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="SessionConfig"></a>
## type [SessionConfig](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/authconfig_types.go#L57-L69>)

SessionConfig defines session/token configuration.

```go
type SessionConfig struct {
    // SigningKey is a reference to the secret containing the JWT signing key.
    // +kubebuilder:validation:Required
    SigningKey SecretKeyRef `json:"signingKey"`
    // TokenExpiry is how long session tokens are valid.
    // +optional
    // +kubebuilder:default="24h"
    TokenExpiry string `json:"tokenExpiry,omitempty"`
    // RefreshExpiry is how long refresh tokens are valid.
    // +optional
    // +kubebuilder:default="7d"
    RefreshExpiry string `json:"refreshExpiry,omitempty"`
}
```

<a name="SessionConfig.DeepCopy"></a>
### func \(\*SessionConfig\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L876>)

```go
func (in *SessionConfig) DeepCopy() *SessionConfig
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SessionConfig.

<a name="SessionConfig.DeepCopyInto"></a>
### func \(\*SessionConfig\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L870>)

```go
func (in *SessionConfig) DeepCopyInto(out *SessionConfig)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="SshKey"></a>
## type [SshKey](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/sshkey_types.go#L41-L46>)

SshKey is the Schema for the sshkeys API. It stores an SSH public key owned by a user. The workspace controller seeds the keys into VM guest cloud\-init user\-data so the guest's sshd trusts them \(enabling passwordless SSH into VM workspaces\). Keys live in the user's personal namespace and apply to every vm workspace created there. \+kubebuilder:object:root=true \+kubebuilder:resource:path=sshkeys,singular=sshkey,scope=Namespaced \+kubebuilder:printcolumn:name="Name",type="string",JSONPath=".spec.name" \+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

```go
type SshKey struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec SshKeySpec `json:"spec,omitempty"`
}
```

<a name="SshKey.DeepCopy"></a>
### func \(\*SshKey\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L894>)

```go
func (in *SshKey) DeepCopy() *SshKey
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SshKey.

<a name="SshKey.DeepCopyInto"></a>
### func \(\*SshKey\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L886>)

```go
func (in *SshKey) DeepCopyInto(out *SshKey)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="SshKey.DeepCopyObject"></a>
### func \(\*SshKey\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L904>)

```go
func (in *SshKey) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="SshKeyList"></a>
## type [SshKeyList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/sshkey_types.go#L51-L55>)

SshKeyList contains a list of SshKey.

```go
type SshKeyList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []SshKey `json:"items"`
}
```

<a name="SshKeyList.DeepCopy"></a>
### func \(\*SshKeyList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L926>)

```go
func (in *SshKeyList) DeepCopy() *SshKeyList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SshKeyList.

<a name="SshKeyList.DeepCopyInto"></a>
### func \(\*SshKeyList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L912>)

```go
func (in *SshKeyList) DeepCopyInto(out *SshKeyList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="SshKeyList.DeepCopyObject"></a>
### func \(\*SshKeyList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L936>)

```go
func (in *SshKeyList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="SshKeySpec"></a>
## type [SshKeySpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/sshkey_types.go#L24-L30>)

SshKeySpec defines the desired state of SshKey.

```go
type SshKeySpec struct {
    // Name is a human-friendly label for this key (e.g. "laptop-2025").
    // +optional
    Name string `json:"name,omitempty"`
    // PublicKey is the SSH public key line (e.g. "ssh-ed25519 AAAA... user@host").
    PublicKey string `json:"publicKey"`
}
```

<a name="SshKeySpec.DeepCopy"></a>
### func \(\*SshKeySpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L949>)

```go
func (in *SshKeySpec) DeepCopy() *SshKeySpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SshKeySpec.

<a name="SshKeySpec.DeepCopyInto"></a>
### func \(\*SshKeySpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L944>)

```go
func (in *SshKeySpec) DeepCopyInto(out *SshKeySpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="User"></a>
## type [User](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L123-L129>)

User is the Schema for the users API. It represents a user account in the kube\-workspaces system.

```go
type User struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   UserSpec   `json:"spec,omitempty"`
    Status UserStatus `json:"status,omitempty"`
}
```

<a name="User.DeepCopy"></a>
### func \(\*User\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L968>)

```go
func (in *User) DeepCopy() *User
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new User.

<a name="User.DeepCopyInto"></a>
### func \(\*User\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L959>)

```go
func (in *User) DeepCopyInto(out *User)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="User.DeepCopyObject"></a>
### func \(\*User\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L978>)

```go
func (in *User) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="UserList"></a>
## type [UserList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L134-L138>)

UserList contains a list of User.

```go
type UserList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []User `json:"items"`
}
```

<a name="UserList.DeepCopy"></a>
### func \(\*UserList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1000>)

```go
func (in *UserList) DeepCopy() *UserList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserList.

<a name="UserList.DeepCopyInto"></a>
### func \(\*UserList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L986>)

```go
func (in *UserList) DeepCopyInto(out *UserList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="UserList.DeepCopyObject"></a>
### func \(\*UserList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1010>)

```go
func (in *UserList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="UserRole"></a>
## type [UserRole](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L25>)

UserRole defines the role level for a user. \+kubebuilder:validation:Enum=admin;editor;viewer

```go
type UserRole string
```

<a name="UserRoleAdmin"></a>

```go
const (
    UserRoleAdmin  UserRole = "admin"
    UserRoleEditor UserRole = "editor"
    UserRoleViewer UserRole = "viewer"
)
```

<a name="UserSpec"></a>
## type [UserSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L59-L83>)

UserSpec defines the desired state of User.

```go
type UserSpec struct {
    // Email is the unique identifier for the user (immutable).
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:Format=email
    Email string `json:"email"`
    // DisplayName is the human-readable name of the user.
    // +optional
    DisplayName string `json:"displayName,omitempty"`
    // Role is the cluster-wide default role for this user.
    // +kubebuilder:default=editor
    Role UserRole `json:"role"`
    // Disabled indicates whether the user account is disabled.
    // +optional
    Disabled bool `json:"disabled,omitempty"`
    // Groups are the groups this user belongs to.
    // +optional
    Groups []string `json:"groups,omitempty"`
    // NamespaceAccess defines additional shared namespace grants beyond the personal namespace.
    // +optional
    NamespaceAccess []NamespaceAccessEntry `json:"namespaceAccess,omitempty"`
    // LocalAuth configures local username/password authentication for this user.
    // May be set alongside other authentication methods (e.g. OIDC) for the same identity.
    // +optional
    LocalAuth *LocalAuthSpec `json:"localAuth,omitempty"`
}
```

<a name="UserSpec.DeepCopy"></a>
### func \(\*UserSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1038>)

```go
func (in *UserSpec) DeepCopy() *UserSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserSpec.

<a name="UserSpec.DeepCopyInto"></a>
### func \(\*UserSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1018>)

```go
func (in *UserSpec) DeepCopyInto(out *UserSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="UserStatus"></a>
## type [UserStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/user_types.go#L86-L110>)

UserStatus defines the observed state of User.

```go
type UserStatus struct {
    // PersonalNamespace is the name of the user's personal namespace (if enabled).
    // +optional
    PersonalNamespace string `json:"personalNamespace,omitempty"`
    // AvatarURL is the URL to the user's avatar image (from OIDC or Gravatar).
    // +optional
    AvatarURL string `json:"avatarURL,omitempty"`
    // LastLogin is the timestamp of the user's last login.
    // +optional
    LastLogin *metav1.Time `json:"lastLogin,omitempty"`
    // LoginCount is the number of times the user has logged in.
    // +optional
    LoginCount int64 `json:"loginCount,omitempty"`
    // FailedLoginAttempts is the number of consecutive failed local login attempts.
    // Reset to 0 on successful login.
    // +optional
    FailedLoginAttempts int `json:"failedLoginAttempts,omitempty"`
    // LockedUntil, if set and in the future, indicates local login is temporarily
    // disabled due to repeated failed attempts.
    // +optional
    LockedUntil *metav1.Time `json:"lockedUntil,omitempty"`
    // Conditions represent the latest available observations of the User's state.
    // +optional
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

<a name="UserStatus.DeepCopy"></a>
### func \(\*UserStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1068>)

```go
func (in *UserStatus) DeepCopy() *UserStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserStatus.

<a name="UserStatus.DeepCopyInto"></a>
### func \(\*UserStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1048>)

```go
func (in *UserStatus) DeepCopyInto(out *UserStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="Workspace"></a>
## type [Workspace](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L83-L89>)

Workspace is the Schema for the workspaces API. It represents a container\-based workspace \(IDE, desktop, etc.\) running in Kubernetes.

```go
type Workspace struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   WorkspaceSpec   `json:"spec,omitempty"`
    Status WorkspaceStatus `json:"status,omitempty"`
}
```

<a name="Workspace.DeepCopy"></a>
### func \(\*Workspace\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1087>)

```go
func (in *Workspace) DeepCopy() *Workspace
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Workspace.

<a name="Workspace.DeepCopyInto"></a>
### func \(\*Workspace\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1078>)

```go
func (in *Workspace) DeepCopyInto(out *Workspace)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="Workspace.DeepCopyObject"></a>
### func \(\*Workspace\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1097>)

```go
func (in *Workspace) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WorkspaceCondition"></a>
## type [WorkspaceCondition](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L46-L63>)

WorkspaceCondition describes the state of a workspace at a certain point.

```go
type WorkspaceCondition struct {
    // Type is the type of the condition. Possible values are Running|Waiting|Terminated
    Type string `json:"type"`
    // Status is the status of the condition. Can be True, False, Unknown.
    Status string `json:"status"`
    // Last time we probed the condition.
    // +optional
    LastProbeTime metav1.Time `json:"lastProbeTime,omitempty"`
    // Last time the condition transitioned from one status to another.
    // +optional
    LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
    // Reason the container is in the current state (brief).
    // +optional
    Reason string `json:"reason,omitempty"`
    // Message regarding why the container is in the current state.
    // +optional
    Message string `json:"message,omitempty"`
}
```

<a name="WorkspaceCondition.DeepCopy"></a>
### func \(\*WorkspaceCondition\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1112>)

```go
func (in *WorkspaceCondition) DeepCopy() *WorkspaceCondition
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceCondition.

<a name="WorkspaceCondition.DeepCopyInto"></a>
### func \(\*WorkspaceCondition\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1105>)

```go
func (in *WorkspaceCondition) DeepCopyInto(out *WorkspaceCondition)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WorkspaceList"></a>
## type [WorkspaceList](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L94-L98>)

WorkspaceList contains a list of Workspace

```go
type WorkspaceList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []Workspace `json:"items"`
}
```

<a name="WorkspaceList.DeepCopy"></a>
### func \(\*WorkspaceList\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1136>)

```go
func (in *WorkspaceList) DeepCopy() *WorkspaceList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceList.

<a name="WorkspaceList.DeepCopyInto"></a>
### func \(\*WorkspaceList\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1122>)

```go
func (in *WorkspaceList) DeepCopyInto(out *WorkspaceList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WorkspaceList.DeepCopyObject"></a>
### func \(\*WorkspaceList\) [DeepCopyObject](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1146>)

```go
func (in *WorkspaceList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WorkspaceSpec"></a>
## type [WorkspaceSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L26-L38>)

WorkspaceSpec defines the desired state of Workspace. Modelled closely on Kubeflow Notebook spec \- wraps a full PodSpec.

```go
type WorkspaceSpec struct {
    // Type selects the workload used to run the workspace.
    // "container" (default) runs the pod template as a StatefulSet.
    // "scratch" runs it as a plain Deployment (no persistent identity).
    // "vm" runs it as a KubeVirt VirtualMachine; the main container image must be
    // a containerDisk image containing a bootable guest disk.
    // +kubebuilder:validation:Enum=container;vm;scratch
    // +kubebuilder:default=container
    // +optional
    Type string `json:"type,omitempty"`
    // Template describes the pod that will be created for the workspace.
    Template WorkspaceTemplateSpec `json:"template"`
}
```

<a name="WorkspaceSpec.DeepCopy"></a>
### func \(\*WorkspaceSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1160>)

```go
func (in *WorkspaceSpec) DeepCopy() *WorkspaceSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceSpec.

<a name="WorkspaceSpec.DeepCopyInto"></a>
### func \(\*WorkspaceSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1154>)

```go
func (in *WorkspaceSpec) DeepCopyInto(out *WorkspaceSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WorkspaceStatus"></a>
## type [WorkspaceStatus](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L66-L73>)

WorkspaceStatus defines the observed state of Workspace.

```go
type WorkspaceStatus struct {
    // Conditions is an array of current conditions
    Conditions []WorkspaceCondition `json:"conditions"`
    // ReadyReplicas is the number of Pods created by the StatefulSet controller that have a Ready Condition.
    ReadyReplicas int32 `json:"readyReplicas"`
    // ContainerState is the state of the underlying workspace container.
    ContainerState corev1.ContainerState `json:"containerState"`
}
```

<a name="WorkspaceStatus.DeepCopy"></a>
### func \(\*WorkspaceStatus\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1183>)

```go
func (in *WorkspaceStatus) DeepCopy() *WorkspaceStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceStatus.

<a name="WorkspaceStatus.DeepCopyInto"></a>
### func \(\*WorkspaceStatus\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1170>)

```go
func (in *WorkspaceStatus) DeepCopyInto(out *WorkspaceStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WorkspaceTemplateSpec"></a>
## type [WorkspaceTemplateSpec](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/workspace_types.go#L41-L43>)

WorkspaceTemplateSpec wraps a PodSpec for the workspace pod.

```go
type WorkspaceTemplateSpec struct {
    Spec corev1.PodSpec `json:"spec"`
}
```

<a name="WorkspaceTemplateSpec.DeepCopy"></a>
### func \(\*WorkspaceTemplateSpec\) [DeepCopy](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1199>)

```go
func (in *WorkspaceTemplateSpec) DeepCopy() *WorkspaceTemplateSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceTemplateSpec.

<a name="WorkspaceTemplateSpec.DeepCopyInto"></a>
### func \(\*WorkspaceTemplateSpec\) [DeepCopyInto](<https://github.com/kube-workspaces/controller/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L1193>)

```go
func (in *WorkspaceTemplateSpec) DeepCopyInto(out *WorkspaceTemplateSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)


# controller

```go
import "github.com/kube-workspaces/controller/internal/controller"
```

Package controller implements the Kubernetes controllers for the kube\-workspaces project. It contains reconcilers for Workspace, User, and AuthConfig custom resources, managing the lifecycle of workspace StatefulSets, user namespaces, RBAC bindings, and authentication configuration.

## Index

- [Constants](<#constants>)
- [Variables](<#variables>)
- [type AuthConfigReconciler](<#AuthConfigReconciler>)
  - [func \(r \*AuthConfigReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#AuthConfigReconciler.Reconcile>)
  - [func \(r \*AuthConfigReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#AuthConfigReconciler.SetupWithManager>)
- [type UserReconciler](<#UserReconciler>)
  - [func \(r \*UserReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#UserReconciler.Reconcile>)
  - [func \(r \*UserReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#UserReconciler.SetupWithManager>)
- [type WorkspaceReconciler](<#WorkspaceReconciler>)
  - [func \(r \*WorkspaceReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#WorkspaceReconciler.Reconcile>)
  - [func \(r \*WorkspaceReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#WorkspaceReconciler.SetupWithManager>)


## Constants

<a name="LocalAuthSystemNamespace"></a>

```go
const (
    // LocalAuthSystemNamespace is where local-auth password Secrets are stored,
    // regardless of the user's personal namespace.
    LocalAuthSystemNamespace = "kube-workspaces-system"

    // PasswordSecretHashKey is the Secret key holding the bcrypt password hash.
    PasswordSecretHashKey = "passwordHash"
    // PasswordSecretPlaintextKey is the Secret key holding the plaintext password.
    // Only present until the user changes their password for the first time.
    PasswordSecretPlaintextKey = "password"

    // DefaultBootstrapAdminEmail is used when AuthConfig.spec.localAuth.bootstrapAdmin.email is unset.
    DefaultBootstrapAdminEmail = "admin@local"
)
```

<a name="UserFinalizer"></a>

```go
const (
    // UserFinalizer is the finalizer added to User CRs.
    UserFinalizer = "kubeworkspaces.io/user-finalizer"
    // LabelManagedByUser indicates the resource is managed by the user controller.
    LabelManagedByUser = "kubeworkspaces.io/managed-by"
    // LabelUserName is the label referencing the owning user.
    LabelUserName = "kubeworkspaces.io/user"
    // LabelPersonalNamespace marks a namespace as a personal namespace.
    LabelPersonalNamespace = "kubeworkspaces.io/personal-namespace"
    // AnnotationUserEmail stores the user's email on managed resources.
    AnnotationUserEmail = "kubeworkspaces.io/user-email"
    // AnnotationNamespaceEnabled marks a namespace as enabled for workspace filtering.
    AnnotationNamespaceEnabled = "kubeworkspaces.io/namespace-enabled"
    // ManagedByValue is the value used for the managed-by label.
    ManagedByValue = "user-controller"
    // LabelValueTrue is the string "true" used in labels.
    LabelValueTrue = "true"
)
```

<a name="DefaultContainerPort"></a>

```go
const (
    // DefaultContainerPort is the default port for workspace containers
    DefaultContainerPort = 8080
    // DefaultServingPort is the port exposed by the Service
    DefaultServingPort = 80
    // AnnotationStopped is the annotation that indicates a workspace is stopped
    AnnotationStopped = "kubeworkspaces.io/stopped"
    // AnnotationReset is the annotation that requests a reset (re-provisioning
    // the workspace from its image, giving it a fresh root volume). The API
    // stamps it with a timestamp so every reset is unique.
    AnnotationReset = "kubeworkspaces.io/reset"
    // LabelWorkspaceName is the label applied to pods to identify the workspace
    LabelWorkspaceName = "workspace-name"
    // LabelKubevirtVM is set by KubeVirt on virt-launcher pods, naming the VMI
    LabelKubevirtVM = "vm.kubevirt.io/name"
    // RootUser is the root account name used for SSH key seeding.
    RootUser = "root"
)
```

<a name="WorkspaceTypeContainer"></a>Workspace workload types \(spec.type\).

```go
const (
    WorkspaceTypeContainer = "container"
    WorkspaceTypeVM        = "vm"
    WorkspaceTypeScratch   = "scratch"
)
```

## Variables

<a name="WorkspacesTotal"></a>

```go
var (
    // WorkspacesTotal is a gauge tracking the total number of workspaces by namespace and status.
    WorkspacesTotal = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "kubeworkspaces_workspaces_total",
            Help: "Total number of workspaces by namespace and status",
        },
        []string{"namespace", "status"},
    )

    // ReconcileTotal is a counter tracking reconciliation attempts by result.
    ReconcileTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kubeworkspaces_workspace_reconcile_total",
            Help: "Total number of workspace reconciliations by result",
        },
        []string{"result"},
    )

    // ReconcileDuration is a histogram tracking reconciliation duration in seconds.
    ReconcileDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "kubeworkspaces_workspace_reconcile_duration_seconds",
            Help:    "Duration of workspace reconciliation in seconds",
            Buckets: prometheus.DefBuckets,
        },
    )

    // WorkspaceReadyTime is a histogram tracking the time from workspace creation to ready state.
    WorkspaceReadyTime = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "kubeworkspaces_workspace_ready_time_seconds",
            Help:    "Time from workspace creation to ready state in seconds",
            Buckets: []float64{5, 10, 30, 60, 120, 300, 600},
        },
    )
)
```

<a name="AuthConfigReconciler"></a>
## type [AuthConfigReconciler](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/authconfig_controller.go#L39-L43>)

AuthConfigReconciler reconciles an AuthConfig object.

```go
type AuthConfigReconciler struct {
    client.Client
    Scheme        *runtime.Scheme
    EventRecorder record.EventRecorder
}
```

<a name="AuthConfigReconciler.Reconcile"></a>
### func \(\*AuthConfigReconciler\) [Reconcile](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/authconfig_controller.go#L51>)

```go
func (r *AuthConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```



<a name="AuthConfigReconciler.SetupWithManager"></a>
### func \(\*AuthConfigReconciler\) [SetupWithManager](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/authconfig_controller.go#L196>)

```go
func (r *AuthConfigReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

<a name="UserReconciler"></a>
## type [UserReconciler](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/user_controller.go#L61-L65>)

UserReconciler reconciles a User object.

```go
type UserReconciler struct {
    client.Client
    Scheme        *runtime.Scheme
    EventRecorder record.EventRecorder
}
```

<a name="UserReconciler.Reconcile"></a>
### func \(\*UserReconciler\) [Reconcile](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/user_controller.go#L76>)

```go
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```



<a name="UserReconciler.SetupWithManager"></a>
### func \(\*UserReconciler\) [SetupWithManager](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/user_controller.go#L393>)

```go
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

<a name="WorkspaceReconciler"></a>
## type [WorkspaceReconciler](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/workspace_controller.go#L95-L102>)

WorkspaceReconciler reconciles a Workspace object

```go
type WorkspaceReconciler struct {
    client.Client
    Scheme        *runtime.Scheme
    EventRecorder record.EventRecorder
    // APIReader bypasses the informer cache for resources the controller does
    // not watch (e.g. Image CRs read for cloud-init seeding).
    APIReader client.Reader
}
```

<a name="WorkspaceReconciler.Reconcile"></a>
### func \(\*WorkspaceReconciler\) [Reconcile](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/workspace_controller.go#L125>)

```go
func (r *WorkspaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```

Reconcile is the main reconciliation loop for Workspace resources. It ensures the workload matching the workspace type \(StatefulSet, Deployment or KubeVirt VirtualMachine\) plus a Service exist for each Workspace CR and keeps the status up to date.

<a name="WorkspaceReconciler.SetupWithManager"></a>
### func \(\*WorkspaceReconciler\) [SetupWithManager](<https://github.com/kube-workspaces/controller/blob/main/internal/controller/workspace_controller.go#L1469>)

```go
func (r *WorkspaceReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)

