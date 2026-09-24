package vm

import (
	"strings"
	"testing"
)

func TestFirstGuestIPv4WhenLeasePresentItShouldSkipLoopback(t *testing.T) {
	got := firstGuestIPv4([]guestIfaceAddrs{
		{Name: "lo", Addrs: []string{"127.0.0.1"}},
		{Name: "enp1s0", Addrs: []string{"192.168.122.50"}},
	})
	if got != "192.168.122.50" {
		t.Fatalf("firstGuestIPv4() = %q, want 192.168.122.50", got)
	}
}

func TestSSHCommandWhenHostSetItShouldTargetThatHost(t *testing.T) {
	v := TestVM{
		SSHHost:     "192.168.122.50",
		SSHPort:     22,
		VMUser:      "user",
		SSHPassword: "user",
	}
	cmd := v.SSHCommand([]string{"true"})
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "user@192.168.122.50") {
		t.Fatalf("ssh args %q do not target guest IP", joined)
	}
	if !strings.Contains(joined, "-p 22") {
		t.Fatalf("ssh args %q do not use port 22", joined)
	}
}

func TestNetworkDeviceXMLWhenNameSetItShouldAttachLibvirtNetwork(t *testing.T) {
	xml := networkDeviceXML("flightctl-net")
	if !strings.Contains(xml, `source network='flightctl-net'`) {
		t.Fatalf("network xml %q missing source", xml)
	}
	if qemuCommandline("flightctl-net", 2233) != "" {
		t.Fatal("bridged guests must not add qemu:commandline (SeaBIOS, no user-net)")
	}
	if strings.Contains(qemuCommandline("flightctl-net", 2233), "hostfwd") {
		t.Fatal("bridged guests must not use QEMU user-net hostfwd")
	}
	if !strings.Contains(xml, `<rom enabled='no'/>`) {
		t.Fatal("bridged NIC must disable PXE option ROM")
	}
}

func TestDiskTargetXMLWhenBridgedItShouldUseSATA(t *testing.T) {
	if !strings.Contains(diskTargetXML("flightctl-net"), `bus="sata"`) {
		t.Fatal("bridged disk must use SATA so OVMF can auto-boot")
	}
	if !strings.Contains(diskTargetXML(""), `bus="virtio"`) {
		t.Fatal("nested disk must stay virtio")
	}
}

func TestCPUXMLWhenBridgedItShouldUseHostModel(t *testing.T) {
	if !strings.Contains(cpuXML("flightctl-net"), `mode='host-model'`) {
		t.Fatal("bridged CPU should match virt-install host-model")
	}
	if !strings.Contains(cpuXML(""), "Haswell-noTSX-IBRS") {
		t.Fatal("nested CPU should stay Haswell-noTSX-IBRS")
	}
}

func TestApplyVMDefaultsWhenNetworkEnvSetItShouldUseBridgedSSHPort(t *testing.T) {
	t.Setenv(EnvVMNetwork, "flightctl-net")
	t.Setenv(EnvLibvirtURI, "qemu+ssh://kni@192.168.122.1/system")

	params := TestVM{SSHPort: 2233, TestDir: t.TempDir(), VMName: "flightctl-e2e-worker-1"}
	applyVMDefaults(&params)
	if params.NetworkName != "flightctl-net" {
		t.Fatalf("NetworkName = %q, want flightctl-net", params.NetworkName)
	}
	if params.SSHPort != bridgedSSHPort {
		t.Fatalf("SSHPort = %d, want %d", params.SSHPort, bridgedSSHPort)
	}
	if params.NvramPath != "" {
		t.Fatal("bridged guests use SeaBIOS and must not allocate OVMF NVRAM")
	}
	if params.LibvirtUri != "qemu+ssh://kni@192.168.122.1/system" {
		t.Fatalf("LibvirtUri = %q", params.LibvirtUri)
	}
}

func TestQemuUserNetCommandlineWhenNetworkEmptyItShouldKeepHostfwd(t *testing.T) {
	xml := qemuCommandline("", 2234)
	if !strings.Contains(xml, "hostfwd=tcp::2234-:22") {
		t.Fatalf("user-net xml %q missing hostfwd", xml)
	}
	if networkDeviceXML("") != "" {
		t.Fatal("nested guests must not attach a libvirt network")
	}
}

func TestOSXMLWhenBridgedItShouldUseSeaBIOS(t *testing.T) {
	bridged := osXML("flightctl-net", "")
	if strings.Contains(bridged, "firmware='efi'") {
		t.Fatal("bridged guests must use SeaBIOS, not OVMF")
	}
	if strings.Contains(bridged, `<boot dev='hd'/>`) {
		t.Fatal("bridged OS xml must not use os/boot together with disk boot order")
	}
	nested := osXML("", "")
	if !strings.Contains(nested, "firmware='efi'") {
		t.Fatal("nested guests must keep UEFI")
	}
}
