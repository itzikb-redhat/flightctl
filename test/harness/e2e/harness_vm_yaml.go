package e2e

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"text/template"
)

//go:embed vm-template.yaml
var vmYAMLTemplateText string

//go:embed cloud-config-fedora.yaml.tmpl
var fedoraCloudConfigTemplateText string

var vmTemplateFuncs = template.FuncMap{
	"indent":    indentLines,
	"yamlQuote": yamlQuote,
}

var vmYAMLTemplate = template.Must(template.New("vm.yaml").Funcs(vmTemplateFuncs).Parse(vmYAMLTemplateText))

var fedoraCloudConfigTemplate = template.Must(
	template.New("cloud-config-fedora").Funcs(vmTemplateFuncs).Parse(fedoraCloudConfigTemplateText),
)

type vmYAMLParams struct {
	Name           string
	GuestMemory    string
	Image          string
	CPUCores       int
	UserData       string
	UserDataBase64 string
	HostDiskPath   string
	ExtraDataSize  string
}

// VMCloudInitWriteFile is an extra cloud-init write_files entry merged into
// VMFedoraNoCloudUserDataWith alongside the default faillock and sudoers files.
type VMCloudInitWriteFile struct {
	Path        string
	Owner       string
	Permissions string
	Content     string
}

type fedoraCloudConfigParams struct {
	GuestUser               string
	Password                string
	FaillockCommand         string
	ForcePasswordSSHCommand string
	EnableSSHDCommand       string
	ExtraWriteFiles         []VMCloudInitWriteFile
	ExtraRuncmds            []string
}

func renderTemplate(tmpl *template.Template, data any) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		panic("rendering " + tmpl.Name() + ": " + err.Error())
	}
	return buf.String()
}

func renderVMYAML(p vmYAMLParams) string {
	return renderTemplate(vmYAMLTemplate, p)
}

func indentLines(spaces int, s string) string {
	if s == "" {
		return ""
	}
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func yamlQuote(s string) string {
	return strconv.Quote(s)
}

// VMYAML builds a KubeVirt VirtualMachine manifest for e2e tests using cloudInitNoCloud userData.
func VMYAML(name, guestMemory, image, cloudInitUserData string) string {
	return renderVMYAML(vmYAMLParams{
		Name:        name,
		GuestMemory: guestMemory,
		Image:       image,
		UserData:    cloudInitUserData,
	})
}

// VMGuestDisableFaillockCommand returns a cloud-init runcmd that removes pam_faillock
// from the PAM stack via authselect and clears any lockout already recorded for user.
// write_files deny=0 in faillock.conf is the persistent setting; this runcmd still
// resets a lock taken in the first-boot window before that file exists. Failures are
// ignored so non-authselect images still boot.
func VMGuestDisableFaillockCommand(user string) string {
	return fmt.Sprintf(`bash -lc "authselect disable-feature with-faillock >/dev/null 2>&1 || true; faillock --user %s --reset >/dev/null 2>&1 || true"`, user)
}

// VMGuestEnableSSHDCommand generates host keys, then enables sshd.service so a
// daemon stays running after reboot instead of Fedora's default sshd.socket.
// Keys must exist first; otherwise sshd exits with "no hostkeys available".
// --no-block keeps nested-VM cloud-init from stalling several minutes on sshd start.
func VMGuestEnableSSHDCommand() string {
	return "ssh-keygen -A; systemctl --no-block mask --now sshd.socket; systemctl unmask sshd.service; systemctl enable sshd.service; systemctl --no-block start sshd.service"
}

// VMGuestForcePasswordSSHCommand makes sshd offer password auth. Fedora's
// 50-redhat.conf sets PasswordAuthentication no and OpenSSH uses the first match,
// so ssh_pwauth alone is not enough; this rewrites that file and reloads sshd.
func VMGuestForcePasswordSSHCommand() string {
	return "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/50-redhat.conf; systemctl reload sshd.service"
}

// VMFedoraNoCloudUserData returns cloud-init userData that sets the fedora
// password, passwordless sudo, and a persistent sshd.service.
func VMFedoraNoCloudUserData(password string) string {
	return VMFedoraNoCloudUserDataWith(password, nil, nil)
}

// VMFedoraNoCloudUserDataWith is VMFedoraNoCloudUserData plus extra write_files and runcmd entries.
func VMFedoraNoCloudUserDataWith(password string, extraWriteFiles []VMCloudInitWriteFile, extraRuncmds []string) string {
	return renderTemplate(fedoraCloudConfigTemplate, fedoraCloudConfigParams{
		GuestUser:               VMFedoraGuestUser,
		Password:                password,
		FaillockCommand:         VMGuestDisableFaillockCommand(VMFedoraGuestUser),
		ForcePasswordSSHCommand: VMGuestForcePasswordSSHCommand(),
		EnableSSHDCommand:       VMGuestEnableSSHDCommand(),
		ExtraWriteFiles:         extraWriteFiles,
		ExtraRuncmds:            extraRuncmds,
	})
}

// VMYAMLWithCPU builds a KubeVirt VirtualMachine manifest. cpuCores <= 0 omits the cpu block.
func VMYAMLWithCPU(name, guestMemory, image string, cpuCores int, cloudInitUserData string) string {
	return renderVMYAML(vmYAMLParams{
		Name:        name,
		GuestMemory: guestMemory,
		Image:       image,
		CPUCores:    cpuCores,
		UserData:    cloudInitUserData,
	})
}

// VMYAMLWithHostVolumes builds a VM manifest with optional hostDisk and blank dataVolume disks.
// An empty hostDiskPath omits host-data. An empty extraDataSize omits extradata.
func VMYAMLWithHostVolumes(name, guestMemory, image, cloudInitUserData, hostDiskPath, extraDataSize string) string {
	return renderVMYAML(vmYAMLParams{
		Name:          name,
		GuestMemory:   guestMemory,
		Image:         image,
		UserData:      cloudInitUserData,
		HostDiskPath:  hostDiskPath,
		ExtraDataSize: extraDataSize,
	})
}

// VMYAMLWithConfigDrive builds a VM manifest using cloudInitConfigDrive userDataBase64.
func VMYAMLWithConfigDrive(name, guestMemory, image, userDataBase64 string) string {
	return renderVMYAML(vmYAMLParams{
		Name:           name,
		GuestMemory:    guestMemory,
		Image:          image,
		UserDataBase64: userDataBase64,
	})
}
