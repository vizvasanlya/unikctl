// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2022, Unikraft GmbH and The KraftKit Authors.
// Licensed under the BSD-3-Clause License (the "License").
// You may not use this file except in compliance with the License.
package qemu

import (
	"encoding/gob"
	"reflect"
	"strings"

	"github.com/spf13/pflag"

	"unikctl.sh/cmdfactory"
)

var qemuShowSgaBiosPreamble bool

func hiddenFlag(flag *pflag.Flag) *pflag.Flag {
	flag.Hidden = true
	return flag
}

func registerGob(v any) {
	safeGobRegister(v)
	registerLegacyGobAlias(v)
}

func safeGobRegister(v any) {
	defer func() {
		if recover() != nil {
			// Ignore duplicate gob registration when legacy/new package paths coexist.
		}
	}()

	gob.Register(v)
}

func registerLegacyGobAlias(v any) {
	t := reflect.TypeOf(v)
	if t == nil {
		return
	}

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Name() == "" || t.PkgPath() == "" {
		return
	}

	legacyPath := strings.Replace(t.PkgPath(), "unikctl.sh/", "kraftkit.sh/", 1)
	if legacyPath == t.PkgPath() {
		return
	}

	safeRegisterLegacyName(legacyPath+"."+t.Name(), v)
}

func safeRegisterLegacyName(name string, v any) {
	defer func() {
		if recover() != nil {
			// Ignore duplicate gob-name registration from mixed legacy/new package paths.
		}
	}()

	gob.RegisterName(name, v)
}

func init() {
	// Register only used supported interfaces later used for serialization.  To
	// include all will roughly increase the final binary size by +20MB.

	// Character devices
	// registerGob(QemuCharDevNull{})
	// registerGob(QemuCharDevSocketTCP{})
	// registerGob(QemuCharDevSocketUnix{})
	// registerGob(QemuCharDevUdp{})
	// registerGob(QemuCharDevVirtualConsole{})
	// registerGob(QemuCharDevRingBuf{})
	// registerGob(QemuCharDevFile{})
	// registerGob(QemuCharDevPipe{})
	// registerGob(QemuCharDevPty{})
	// registerGob(QemuCharDevStdio{})
	// registerGob(QemuCharDevSerial{})
	// registerGob(QemuCharDevTty{})
	// registerGob(QemuCharDevParallel{})
	// registerGob(QemuCharDevParport{})
	// registerGob(QemuCharDevSpiceVMC{})
	// registerGob(QemuCharDevSpicePort{})

	// Host character devices
	// registerGob(QemuHostCharDevVirtualConsole{})
	// registerGob(QemuHostCharDevPty{})
	registerGob(QemuHostCharDevNone{})
	// registerGob(QemuHostCharDevNull{})
	// registerGob(QemuHostCharDevNamed{})
	// registerGob(QemuHostCharDevTty{})
	registerGob(QemuHostCharDevFile{})
	// registerGob(QemuHostCharDevStdio{})
	// registerGob(QemuHostCharDevPipe{})
	// registerGob(QemuHostCharDevUDP{})
	// registerGob(QemuHostCharDevTCP{})
	// registerGob(QemuHostCharDevTelnet{})
	// registerGob(QemuHostCharDevWebsocket{})
	registerGob(QemuHostCharDevUnix{})

	// CPU devices
	// registerGob(QemuDevice486V1X8664Cpu{})
	// registerGob(QemuDevice486X8664Cpu{})
	// registerGob(QemuDeviceAthlonV1X8664Cpu{})
	// registerGob(QemuDeviceAthlonX8664Cpu{})
	// registerGob(QemuDeviceBaseX8664Cpu{})
	// registerGob(QemuDeviceBroadwellIbrsX8664Cpu{})
	// registerGob(QemuDeviceBroadwellNotsxIbrsX8664Cpu{})
	// registerGob(QemuDeviceBroadwellNotsxX8664Cpu{})
	// registerGob(QemuDeviceBroadwellV1X8664Cpu{})
	// registerGob(QemuDeviceBroadwellV2X8664Cpu{})
	// registerGob(QemuDeviceBroadwellV3X8664Cpu{})
	// registerGob(QemuDeviceBroadwellV4X8664Cpu{})
	// registerGob(QemuDeviceBroadwellX8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerNotsxX8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerV1X8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerV2X8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerV3X8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerV4X8664Cpu{})
	// registerGob(QemuDeviceCascadelakeServerX8664Cpu{})
	// registerGob(QemuDeviceConroeV1X8664Cpu{})
	// registerGob(QemuDeviceConroeX8664Cpu{})
	// registerGob(QemuDeviceCooperlakeV1X8664Cpu{})
	// registerGob(QemuDeviceCooperlakeX8664Cpu{})
	// registerGob(QemuDeviceCore2duoV1X8664Cpu{})
	// registerGob(QemuDeviceCore2duoX8664Cpu{})
	// registerGob(QemuDeviceCoreduoV1X8664Cpu{})
	// registerGob(QemuDeviceCoreduoX8664Cpu{})
	// registerGob(QemuDeviceDenvertonV1X8664Cpu{})
	// registerGob(QemuDeviceDenvertonV2X8664Cpu{})
	// registerGob(QemuDeviceDenvertonX8664Cpu{})
	// registerGob(QemuDeviceDhyanaV1X8664Cpu{})
	// registerGob(QemuDeviceDhyanaX8664Cpu{})
	// registerGob(QemuDeviceEpycIbpbX8664Cpu{})
	// registerGob(QemuDeviceEpycRomeV1X8664Cpu{})
	// registerGob(QemuDeviceEpycRomeX8664Cpu{})
	// registerGob(QemuDeviceEpycV1X8664Cpu{})
	// registerGob(QemuDeviceEpycV2X8664Cpu{})
	// registerGob(QemuDeviceEpycV3X8664Cpu{})
	// registerGob(QemuDeviceEpycX8664Cpu{})
	// registerGob(QemuDeviceHaswellIbrsX8664Cpu{})
	// registerGob(QemuDeviceHaswellNotsxIbrsX8664Cpu{})
	// registerGob(QemuDeviceHaswellNotsxX8664Cpu{})
	// registerGob(QemuDeviceHaswellV1X8664Cpu{})
	// registerGob(QemuDeviceHaswellV2X8664Cpu{})
	// registerGob(QemuDeviceHaswellV3X8664Cpu{})
	// registerGob(QemuDeviceHaswellV4X8664Cpu{})
	// registerGob(QemuDeviceHaswellX8664Cpu{})
	// registerGob(QemuDeviceHostX8664Cpu{})
	// registerGob(QemuDeviceIcelakeClientNotsxX8664Cpu{})
	// registerGob(QemuDeviceIcelakeClientV1X8664Cpu{})
	// registerGob(QemuDeviceIcelakeClientV2X8664Cpu{})
	// registerGob(QemuDeviceIcelakeClientX8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerNotsxX8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerV1X8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerV2X8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerV3X8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerV4X8664Cpu{})
	// registerGob(QemuDeviceIcelakeServerX8664Cpu{})
	// registerGob(QemuDeviceIvybridgeIbrsX8664Cpu{})
	// registerGob(QemuDeviceIvybridgeV1X8664Cpu{})
	// registerGob(QemuDeviceIvybridgeV2X8664Cpu{})
	// registerGob(QemuDeviceIvybridgeX8664Cpu{})
	// registerGob(QemuDeviceKnightsmillV1X8664Cpu{})
	// registerGob(QemuDeviceKnightsmillX8664Cpu{})
	// registerGob(QemuDeviceKvm32V1X8664Cpu{})
	// registerGob(QemuDeviceKvm32X8664Cpu{})
	// registerGob(QemuDeviceKvm64V1X8664Cpu{})
	// registerGob(QemuDeviceKvm64X8664Cpu{})
	// registerGob(QemuDeviceMaxX8664Cpu{})
	// registerGob(QemuDeviceN270V1X8664Cpu{})
	// registerGob(QemuDeviceN270X8664Cpu{})
	// registerGob(QemuDeviceNehalemIbrsX8664Cpu{})
	// registerGob(QemuDeviceNehalemV1X8664Cpu{})
	// registerGob(QemuDeviceNehalemV2X8664Cpu{})
	// registerGob(QemuDeviceNehalemX8664Cpu{})
	// registerGob(QemuDeviceOpteronG1V1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG2V1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG2X8664Cpu{})
	// registerGob(QemuDeviceOpteronG3V1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG3X8664Cpu{})
	// registerGob(QemuDeviceOpteronG4V1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG4X8664Cpu{})
	// registerGob(QemuDeviceOpteronG5V1X8664Cpu{})
	// registerGob(QemuDeviceOpteronG5X8664Cpu{})
	// registerGob(QemuDevicePenrynV1X8664Cpu{})
	// registerGob(QemuDevicePenrynX8664Cpu{})
	// registerGob(QemuDevicePentiumV1X8664Cpu{})
	// registerGob(QemuDevicePentiumX8664Cpu{})
	// registerGob(QemuDevicePentium2V1X8664Cpu{})
	// registerGob(QemuDevicePentium2X8664Cpu{})
	// registerGob(QemuDevicePentium3V1X8664Cpu{})
	// registerGob(QemuDevicePentium3X8664Cpu{})
	// registerGob(QemuDevicePhenomV1X8664Cpu{})
	// registerGob(QemuDevicePhenomX8664Cpu{})
	// registerGob(QemuDeviceQemu32V1X8664Cpu{})
	// registerGob(QemuDeviceQemu32X8664Cpu{})
	// registerGob(QemuDeviceQemu64V1X8664Cpu{})
	// registerGob(QemuDeviceQemu64X8664Cpu{})
	// registerGob(QemuDeviceSandybridgeIbrsX8664Cpu{})
	// registerGob(QemuDeviceSandybridgeV1X8664Cpu{})
	// registerGob(QemuDeviceSandybridgeV2X8664Cpu{})
	// registerGob(QemuDeviceSandybridgeX8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientIbrsX8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientNotsxIbrsX8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientV1X8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientV2X8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientV3X8664Cpu{})
	// registerGob(QemuDeviceSkylakeClientX8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerIbrsX8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerNotsxIbrsX8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerV1X8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerV2X8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerV3X8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerV4X8664Cpu{})
	// registerGob(QemuDeviceSkylakeServerX8664Cpu{})
	// registerGob(QemuDeviceSnowridgeV1X8664Cpu{})
	// registerGob(QemuDeviceSnowridgeV2X8664Cpu{})
	// registerGob(QemuDeviceSnowridgeX8664Cpu{})
	// registerGob(QemuDeviceWestmereIbrsX8664Cpu{})
	// registerGob(QemuDeviceWestmereV1X8664Cpu{})
	// registerGob(QemuDeviceWestmereV2X8664Cpu{})
	// registerGob(QemuDeviceWestmereX8664Cpu{})

	// Controller/Bridge/Hub devices
	// registerGob(QemuDeviceI82801b11Bridge{})
	// registerGob(QemuDeviceIgdPassthroughIsaBridge{})
	// registerGob(QemuDeviceIoh3420{})
	// registerGob(QemuDevicePciBridge{})
	// registerGob(QemuDevicePciBridgeSeat{})
	// registerGob(QemuDevicePciePciBridge{})
	// registerGob(QemuDevicePcieRootPort{})
	// registerGob(QemuDevicePxb{})
	// registerGob(QemuDevicePxbPcie{})
	// registerGob(QemuDeviceUsbHost{})
	// registerGob(QemuDeviceUsbHub{})
	// registerGob(QemuDeviceVfioPciIgdLpcBridge{})
	// registerGob(QemuDeviceVmbusBridge{})
	// registerGob(QemuDeviceX3130Upstream{})
	// registerGob(QemuDeviceXio3130Downstream{})

	// Display devices
	// registerGob(QemuDeviceAtiVga{})
	// registerGob(QemuDeviceBochsDisplay{})
	// registerGob(QemuDeviceCirrusVga{})
	// registerGob(QemuDeviceIsaCirrusVga{})
	// registerGob(QemuDeviceIsaVga{})
	// registerGob(QemuDeviceQxl{})
	// registerGob(QemuDeviceQxlVga{})
	// registerGob(QemuDeviceRamfb{})
	// registerGob(QemuDeviceSecondaryVga{})
	registerGob(QemuDeviceSga{})
	// registerGob(QemuDeviceVga{})
	// registerGob(QemuDeviceVhostUserGpu{})
	// registerGob(QemuDeviceVhostUserGpuPci{})
	// registerGob(QemuDeviceVhostUserVga{})
	// registerGob(QemuDeviceVirtioGpuDevice{})
	// registerGob(QemuDeviceVirtioGpuPci{})
	// registerGob(QemuDeviceVirtioVga{})
	// registerGob(QemuDeviceVmwareSvga{})

	// Input devices
	// registerGob(QemuDeviceCcidCardEmulated{})
	// registerGob(QemuDeviceCcidCardPassthru{})
	// registerGob(QemuDeviceI8042{})
	// registerGob(QemuDeviceIpoctal232{})
	// registerGob(QemuDeviceIsaParallel{})
	// registerGob(QemuDeviceIsaSerial{})
	// registerGob(QemuDevicePciSerial{})
	// registerGob(QemuDevicePciSerial2x{})
	// registerGob(QemuDevicePciSerial4x{})
	// registerGob(QemuDeviceTpci200{})
	// registerGob(QemuDeviceUsbBraille{})
	// registerGob(QemuDeviceUsbCcid{})
	// registerGob(QemuDeviceUsbKbd{})
	// registerGob(QemuDeviceUsbMouse{})
	// registerGob(QemuDeviceUsbSerial{})
	// registerGob(QemuDeviceUsbTablet{})
	// registerGob(QemuDeviceUsbWacomTablet{})
	// registerGob(QemuDeviceVhostUserInput{})
	// registerGob(QemuDeviceVhostUserInputPci{})
	// registerGob(QemuDeviceVirtconsole{})
	// registerGob(QemuDeviceVirtioInputHostDevice{})
	// registerGob(QemuDeviceVirtioInputHostPci{})
	// registerGob(QemuDeviceVirtioKeyboardDevice{})
	// registerGob(QemuDeviceVirtioKeyboardPci{})
	// registerGob(QemuDeviceVirtioMouseDevice{})
	// registerGob(QemuDeviceVirtioMousePci{})
	// registerGob(QemuDeviceVirtioSerialDevice{})
	// registerGob(QemuDeviceVirtioSerialPci{})
	// registerGob(QemuDeviceVirtioSerialPciNonTransitional{})
	// registerGob(QemuDeviceVirtioSerialPciTransitional{})
	// registerGob(QemuDeviceVirtioTabletDevice{})
	// registerGob(QemuDeviceVirtioTabletPci{})
	// registerGob(QemuDeviceVirtserialport{})

	// Misc devices
	// registerGob(QemuDeviceAmdIommu{})
	// registerGob(QemuDeviceCtucanPci{})
	// registerGob(QemuDeviceEdu{})
	// registerGob(QemuDeviceHypervTestdev{})
	// registerGob(QemuDeviceI2cDdc{})
	// registerGob(QemuDeviceI6300esb{})
	// registerGob(QemuDeviceIb700{})
	// registerGob(QemuDeviceIntelIommu{})
	// registerGob(QemuDeviceIsaApplesmc{})
	// registerGob(QemuDeviceIsaDebugExit{})
	// registerGob(QemuDeviceIsaDebugcon{})
	// registerGob(QemuDeviceIvshmemDoorbell{})
	// registerGob(QemuDeviceIvshmemPlain{})
	// registerGob(QemuDeviceKvaserPci{})
	// registerGob(QemuDeviceLoader{})
	// registerGob(QemuDeviceMioe3680Pci{})
	// registerGob(QemuDevicePcTestdev{})
	// registerGob(QemuDevicePciTestdev{})
	// registerGob(QemuDevicePcm3680Pci{})
	registerGob(QemuDevicePvpanic{})
	// registerGob(QemuDeviceSmbusIpmi{})
	// registerGob(QemuDeviceTpmCrb{})
	// registerGob(QemuDeviceUsbRedir{})
	// registerGob(QemuDeviceVfioPci{})
	// registerGob(QemuDeviceVfioPciNohotplug{})
	// registerGob(QemuDeviceVhostUserVsockDevice{})
	// registerGob(QemuDeviceVhostUserVsockPci{})
	// registerGob(QemuDeviceVhostUserVsockPciNonTransitional{})
	// registerGob(QemuDeviceVhostVsockDevice{})
	// registerGob(QemuDeviceVhostVsockPci{})
	// registerGob(QemuDeviceVhostVsockPciNonTransitional{})
	// registerGob(QemuDeviceVirtioBalloonDevice{})
	// registerGob(QemuDeviceVirtioBalloonPci{})
	// registerGob(QemuDeviceVirtioBalloonPciNonTransitional{})
	// registerGob(QemuDeviceVirtioBalloonPciTransitional{})
	// registerGob(QemuDeviceVirtioCryptoDevice{})
	// registerGob(QemuDeviceVirtioCryptoPci{})
	// registerGob(QemuDeviceVirtioIommuDevice{})
	// registerGob(QemuDeviceVirtioIommuPci{})
	// registerGob(QemuDeviceVirtioIommuPciNonTransitional{})
	// registerGob(QemuDeviceVirtioMem{})
	// registerGob(QemuDeviceVirtioMemPci{})
	// registerGob(QemuDeviceVirtioPmemPci{})
	// registerGob(QemuDeviceVirtioRngDevice{})
	// registerGob(QemuDeviceVirtioRngPci{})
	// registerGob(QemuDeviceVirtioRngPciNonTransitional{})
	// registerGob(QemuDeviceVirtioRngPciTransitional{})
	// registerGob(QemuDeviceVmcoreinfo{})
	// registerGob(QemuDeviceVmgenid{})
	// registerGob(QemuDeviceXenBackend{})
	// registerGob(QemuDeviceXenPciPassthrough{})
	// registerGob(QemuDeviceXenPlatform{})

	// Network devices
	// registerGob(QemuDeviceE1000{})
	// registerGob(QemuDeviceE100082544gc{})
	// registerGob(QemuDeviceE100082545em{})
	// registerGob(QemuDeviceE1000e{})
	// registerGob(QemuDeviceI82550{})
	// registerGob(QemuDeviceI82551{})
	// registerGob(QemuDeviceI82557a{})
	// registerGob(QemuDeviceI82557b{})
	// registerGob(QemuDeviceI82557c{})
	// registerGob(QemuDeviceI82558a{})
	// registerGob(QemuDeviceI82558b{})
	// registerGob(QemuDeviceI82559a{})
	// registerGob(QemuDeviceI82559b{})
	// registerGob(QemuDeviceI82559c{})
	// registerGob(QemuDeviceI82559er{})
	// registerGob(QemuDeviceI82562{})
	// registerGob(QemuDeviceI82801{})
	// registerGob(QemuDeviceNe2kIsa{})
	// registerGob(QemuDeviceNe2kPci{})
	// registerGob(QemuDevicePcnet{})
	// registerGob(QemuDevicePvrdma{})
	// registerGob(QemuDeviceRocker{})
	// registerGob(QemuDeviceRtl8139{})
	// registerGob(QemuDeviceTulip{})
	// registerGob(QemuDeviceUsbNet{})
	// registerGob(QemuDeviceVirtioNetDevice{})
	registerGob(QemuDeviceVirtioNetPci{})
	// registerGob(QemuDeviceVirtioNetPciNonTransitional{})
	// registerGob(QemuDeviceVirtioNetPciTransitional{})
	// registerGob(QemuDeviceVmxnet3{})

	// Sound devices
	// registerGob(QemuDeviceAc97{})
	// registerGob(QemuDeviceAdlib{})
	// registerGob(QemuDeviceCs4231a{})
	// registerGob(QemuDeviceEs1370{})
	// registerGob(QemuDeviceGus{})
	// registerGob(QemuDeviceHdaDuplex{})
	// registerGob(QemuDeviceHdaMicro{})
	// registerGob(QemuDeviceHdaOutput{})
	// registerGob(QemuDeviceIch9IntelHda{})
	// registerGob(QemuDeviceIntelHda{})
	// registerGob(QemuDeviceSb16{})
	// registerGob(QemuDeviceUsbAudio{})

	// Storage devices
	// registerGob(QemuDeviceAm53c974{})
	// registerGob(QemuDeviceDc390{})
	// registerGob(QemuDeviceFloppy{})
	// registerGob(QemuDeviceIch9Ahci{})
	// registerGob(QemuDeviceIdeCd{})
	// registerGob(QemuDeviceIdeDrive{})
	// registerGob(QemuDeviceIdeHd{})
	// registerGob(QemuDeviceIsaFdc{})
	// registerGob(QemuDeviceIsaIde{})
	// registerGob(QemuDeviceLsi53c810{})
	// registerGob(QemuDeviceLsi53c895a{})
	// registerGob(QemuDeviceMegasas{})
	// registerGob(QemuDeviceMegasasGen2{})
	// registerGob(QemuDeviceMptsas1068{})
	// registerGob(QemuDeviceNvme{})
	// registerGob(QemuDeviceNvmeNs{})
	// registerGob(QemuDevicePiix3Ide{})
	// registerGob(QemuDevicePiix3IdeXen{})
	// registerGob(QemuDevicePiix4Ide{})
	// registerGob(QemuDevicePvscsi{})
	// registerGob(QemuDeviceScsiBlock{})
	// registerGob(QemuDeviceScsiCd{})
	// registerGob(QemuDeviceScsiDisk{})
	// registerGob(QemuDeviceScsiGeneric{})
	// registerGob(QemuDeviceScsiHd{})
	// registerGob(QemuDeviceSdCard{})
	// registerGob(QemuDeviceSdhciPci{})
	// registerGob(QemuDeviceUsbBot{})
	// registerGob(QemuDeviceUsbMtp{})
	// registerGob(QemuDeviceUsbStorage{})
	// registerGob(QemuDeviceUsbUas{})
	// registerGob(QemuDeviceVhostScsi{})
	// registerGob(QemuDeviceVhostScsiPci{})
	// registerGob(QemuDeviceVhostScsiPciNonTransitional{})
	// registerGob(QemuDeviceVhostScsiPciTransitional{})
	// registerGob(QemuDeviceVhostUserBlk{})
	// registerGob(QemuDeviceVhostUserBlkPci{})
	// registerGob(QemuDeviceVhostUserBlkPciNonTransitional{})
	// registerGob(QemuDeviceVhostUserBlkPciTransitional{})
	// registerGob(QemuDeviceVhostUserFsDevice{})
	// registerGob(QemuDeviceVhostUserFsPci{})
	// registerGob(QemuDeviceVhostUserScsi{})
	// registerGob(QemuDeviceVhostUserScsiPci{})
	// registerGob(QemuDeviceVhostUserScsiPciNonTransitional{})
	// registerGob(QemuDeviceVhostUserScsiPciTransitional{})
	// registerGob(QemuDeviceVirtio9pDevice{})
	registerGob(QemuDeviceVirtio9pPci{})
	// registerGob(QemuDeviceVirtio9pPciNonTransitional{})
	// registerGob(QemuDeviceVirtio9pPciTransitional{})
	// registerGob(QemuDeviceVirtioBlkDevice{})
	// registerGob(QemuDeviceVirtioBlkPci{})
	// registerGob(QemuDeviceVirtioBlkPciNonTransitional{})
	// registerGob(QemuDeviceVirtioBlkPciTransitional{})
	// registerGob(QemuDeviceVirtioScsiDevice{})
	// registerGob(QemuDeviceVirtioScsiPci{})
	// registerGob(QemuDeviceVirtioScsiPciNonTransitional{})
	// registerGob(QemuDeviceVirtioScsiPciTransitional{})

	// USB devices
	// registerGob(QemuDeviceIch9UsbEhci1{})
	// registerGob(QemuDeviceIch9UsbEhci2{})
	// registerGob(QemuDeviceIch9UsbUhci1{})
	// registerGob(QemuDeviceIch9UsbUhci2{})
	// registerGob(QemuDeviceIch9UsbUhci3{})
	// registerGob(QemuDeviceIch9UsbUhci4{})
	// registerGob(QemuDeviceIch9UsbUhci5{})
	// registerGob(QemuDeviceIch9UsbUhci6{})
	// registerGob(QemuDeviceNecUsbXhci{})
	// registerGob(QemuDevicePciOhci{})
	// registerGob(QemuDevicePiix3UsbUhci{})
	// registerGob(QemuDevicePiix4UsbUhci{})
	// registerGob(QemuDeviceQemuXhci{})
	// registerGob(QemuDeviceUsbEhci{})
	// registerGob(QemuDeviceVt82c686bUsbUhci{})

	// Uncategorized devices
	// registerGob(QemuDeviceAmdviPci{})
	// registerGob(QemuDeviceIpmiBmcExtern{})
	// registerGob(QemuDeviceIpmiBmcSim{})
	// registerGob(QemuDeviceIsaIpmiBt{})
	// registerGob(QemuDeviceIsaIpmiKcs{})
	// registerGob(QemuDeviceMc146818rtc{})
	// registerGob(QemuDeviceNvdimm{})
	// registerGob(QemuDevicePcDimm{})
	// registerGob(QemuDevicePciIpmiBt{})
	// registerGob(QemuDevicePciIpmiKcs{})
	// registerGob(QemuDeviceTpmTis{})
	// registerGob(QemuDeviceU2fPassthru{})
	// registerGob(QemuDeviceVirtioPmem{})
	// registerGob(QemuDeviceVmmouse{})
	// registerGob(QemuDeviceXenCdrom{})
	// registerGob(QemuDeviceXenDisk{})
	// registerGob(QemuDeviceXenPvdevice{})

	// CPUs
	registerGob(QemuCPU{})
	registerGob(QemuCPUX86(""))
	registerGob(QemuCPUArm(""))

	// Displays
	// registerGob(QemuDisplaySpiceApp{})
	// registerGob(QemuDisplayGtk{})
	// registerGob(QemuDisplayVNC{})
	// registerGob(QemuDisplayCurses{})
	// registerGob(QemuDisplayEglHeadless{})
	registerGob(QemuDisplayNone{})

	// Network Devices
	// registerGob(QemuNetDevBridge{})
	// registerGob(QemuNetDevHubport{})
	// registerGob(QemuNetDevL2tpv3{})
	// registerGob(QemuNetDevSocket{})
	registerGob(QemuNetDevTap{})
	registerGob(QemuNetDevUser{})
	// registerGob(QemuNetDevVde{})
	// registerGob(QemuNetDevVhostUser{})
	// registerGob(QemuNetDevVhostVdpa{})

	// Filesystem Devices
	registerGob(QemuFsDevLocal{})
	// registerGob(QemuFsDevProxy{})
	// registerGob(QemuFsDevSynth{})
	registerGob(QemuFsDevLocalSecurityModelMappedXattr)

	// CLI configuration
	registerGob(QemuConfig{})
}

func RegisterFlags() {
	// Register additional command-line arguments
	cmdfactory.RegisterFlag(
		"unikctl run",
		hiddenFlag(cmdfactory.BoolVar(
			&qemuShowSgaBiosPreamble,
			"qemu-sgabios-preamble",
			false,
			"Show the QEMU SGABIOS preamble when running a unikernel",
		)),
	)
}
