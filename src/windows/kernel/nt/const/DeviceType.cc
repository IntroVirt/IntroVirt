/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <introvirt/windows/kernel/nt/const/DeviceType.hh>

namespace introvirt {
namespace windows {
namespace nt {

const std::string& to_string(DeviceType type) {
    const static std::string FILE_DEVICE_BEEPStr = "FILE_DEVICE_BEEP";
    const static std::string FILE_DEVICE_CD_ROMStr = "FILE_DEVICE_CD_ROM";
    const static std::string FILE_DEVICE_CD_ROM_FILE_SYSTEMStr = "FILE_DEVICE_CD_ROM_FILE_SYSTEM";
    const static std::string FILE_DEVICE_CONTROLLERStr = "FILE_DEVICE_CONTROLLER";
    const static std::string FILE_DEVICE_DATALINKStr = "FILE_DEVICE_DATALINK";
    const static std::string FILE_DEVICE_DFSStr = "FILE_DEVICE_DFS";
    const static std::string FILE_DEVICE_DISKStr = "FILE_DEVICE_DISK";
    const static std::string FILE_DEVICE_DISK_FILE_SYSTEMStr = "FILE_DEVICE_DISK_FILE_SYSTEM";
    const static std::string FILE_DEVICE_FILE_SYSTEMStr = "FILE_DEVICE_FILE_SYSTEM";
    const static std::string FILE_DEVICE_INPORT_PORTStr = "FILE_DEVICE_INPORT_PORT";
    const static std::string FILE_DEVICE_KEYBOARDStr = "FILE_DEVICE_KEYBOARD";
    const static std::string FILE_DEVICE_MAILSLOTStr = "FILE_DEVICE_MAILSLOT";
    const static std::string FILE_DEVICE_MIDI_INStr = "FILE_DEVICE_MIDI_IN";
    const static std::string FILE_DEVICE_MIDI_OUTStr = "FILE_DEVICE_MIDI_OUT";
    const static std::string FILE_DEVICE_MOUSEStr = "FILE_DEVICE_MOUSE";
    const static std::string FILE_DEVICE_MULTI_UNC_PROVIDERStr = "FILE_DEVICE_MULTI_UNC_PROVIDER";
    const static std::string FILE_DEVICE_NAMED_PIPEStr = "FILE_DEVICE_NAMED_PIPE";
    const static std::string FILE_DEVICE_NETWORKStr = "FILE_DEVICE_NETWORK";
    const static std::string FILE_DEVICE_NETWORK_BROWSERStr = "FILE_DEVICE_NETWORK_BROWSER";
    const static std::string FILE_DEVICE_NETWORK_FILE_SYSTEMStr = "FILE_DEVICE_NETWORK_FILE_SYSTEM";
    const static std::string FILE_DEVICE_NULLStr = "FILE_DEVICE_NULL";
    const static std::string FILE_DEVICE_PARALLEL_PORTStr = "FILE_DEVICE_PARALLEL_PORT";
    const static std::string FILE_DEVICE_PHYSICAL_NETCARDStr = "FILE_DEVICE_PHYSICAL_NETCARD";
    const static std::string FILE_DEVICE_PRINTERStr = "FILE_DEVICE_PRINTER";
    const static std::string FILE_DEVICE_SCANNERStr = "FILE_DEVICE_SCANNER";
    const static std::string FILE_DEVICE_SERIAL_MOUSE_PORTStr = "FILE_DEVICE_SERIAL_MOUSE_PORT";
    const static std::string FILE_DEVICE_SERIAL_PORTStr = "FILE_DEVICE_SERIAL_PORT";
    const static std::string FILE_DEVICE_SCREENStr = "FILE_DEVICE_SCREEN";
    const static std::string FILE_DEVICE_SOUNDStr = "FILE_DEVICE_SOUND";
    const static std::string FILE_DEVICE_STREAMSStr = "FILE_DEVICE_STREAMS";
    const static std::string FILE_DEVICE_TAPEStr = "FILE_DEVICE_TAPE";
    const static std::string FILE_DEVICE_TAPE_FILE_SYSTEMStr = "FILE_DEVICE_TAPE_FILE_SYSTEM";
    const static std::string FILE_DEVICE_TRANSPORTStr = "FILE_DEVICE_TRANSPORT";
    const static std::string FILE_DEVICE_UNKNOWNStr = "FILE_DEVICE_UNKNOWN";
    const static std::string FILE_DEVICE_VIDEOStr = "FILE_DEVICE_VIDEO";
    const static std::string FILE_DEVICE_VIRTUAL_DISKStr = "FILE_DEVICE_VIRTUAL_DISK";
    const static std::string FILE_DEVICE_WAVE_INStr = "FILE_DEVICE_WAVE_IN";
    const static std::string FILE_DEVICE_WAVE_OUTStr = "FILE_DEVICE_WAVE_OUT";
    const static std::string FILE_DEVICE_8042_PORTStr = "FILE_DEVICE_8042_PORT";
    const static std::string FILE_DEVICE_NETWORK_REDIRECTORStr = "FILE_DEVICE_NETWORK_REDIRECTOR";
    const static std::string FILE_DEVICE_BATTERYStr = "FILE_DEVICE_BATTERY";
    const static std::string FILE_DEVICE_BUS_EXTENDERStr = "FILE_DEVICE_BUS_EXTENDER";
    const static std::string FILE_DEVICE_MODEMStr = "FILE_DEVICE_MODEM";
    const static std::string FILE_DEVICE_VDMStr = "FILE_DEVICE_VDM";
    const static std::string FILE_DEVICE_MASS_STORAGEStr = "FILE_DEVICE_MASS_STORAGE";
    const static std::string FILE_DEVICE_SMBStr = "FILE_DEVICE_SMB";
    const static std::string FILE_DEVICE_KSStr = "FILE_DEVICE_KS";
    const static std::string FILE_DEVICE_CHANGERStr = "FILE_DEVICE_CHANGER";
    const static std::string FILE_DEVICE_SMARTCARDStr = "FILE_DEVICE_SMARTCARD";
    const static std::string FILE_DEVICE_ACPIStr = "FILE_DEVICE_ACPI";
    const static std::string FILE_DEVICE_DVDStr = "FILE_DEVICE_DVD";
    const static std::string FILE_DEVICE_FULLSCREEN_VIDEOStr = "FILE_DEVICE_FULLSCREEN_VIDEO";
    const static std::string FILE_DEVICE_DFS_FILE_SYSTEMStr = "FILE_DEVICE_DFS_FILE_SYSTEM";
    const static std::string FILE_DEVICE_DFS_VOLUMEStr = "FILE_DEVICE_DFS_VOLUME";
    const static std::string FILE_DEVICE_SERENUMStr = "FILE_DEVICE_SERENUM";
    const static std::string FILE_DEVICE_TERMSRVStr = "FILE_DEVICE_TERMSRV";
    const static std::string FILE_DEVICE_KSECStr = "FILE_DEVICE_KSEC";
    const static std::string FILE_DEVICE_FIPSStr = "FILE_DEVICE_FIPS";
    const static std::string FILE_DEVICE_INFINIBANDStr = "FILE_DEVICE_INFINIBAND";
    const static std::string FILE_DEVICE_VMBUSStr = "FILE_DEVICE_VMBUS";
    const static std::string FILE_DEVICE_CRYPT_PROVIDERStr = "FILE_DEVICE_CRYPT_PROVIDER";
    const static std::string FILE_DEVICE_WPDStr = "FILE_DEVICE_WPD";
    const static std::string FILE_DEVICE_BLUETOOTHStr = "FILE_DEVICE_BLUETOOTH";
    const static std::string FILE_DEVICE_MT_COMPOSITEStr = "FILE_DEVICE_MT_COMPOSITE";
    const static std::string FILE_DEVICE_MT_TRANSPORTStr = "FILE_DEVICE_MT_TRANSPORT";
    const static std::string FILE_DEVICE_BIOMETRICStr = "FILE_DEVICE_BIOMETRIC";
    const static std::string FILE_DEVICE_PMIStr = "FILE_DEVICE_PMI";

    switch (type) {
    case DeviceType::FILE_DEVICE_BEEP:
        return FILE_DEVICE_BEEPStr;
    case DeviceType::FILE_DEVICE_CD_ROM:
        return FILE_DEVICE_CD_ROMStr;
    case DeviceType::FILE_DEVICE_CD_ROM_FILE_SYSTEM:
        return FILE_DEVICE_CD_ROM_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_CONTROLLER:
        return FILE_DEVICE_CONTROLLERStr;
    case DeviceType::FILE_DEVICE_DATALINK:
        return FILE_DEVICE_DATALINKStr;
    case DeviceType::FILE_DEVICE_DFS:
        return FILE_DEVICE_DFSStr;
    case DeviceType::FILE_DEVICE_DISK:
        return FILE_DEVICE_DISKStr;
    case DeviceType::FILE_DEVICE_DISK_FILE_SYSTEM:
        return FILE_DEVICE_DISK_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_FILE_SYSTEM:
        return FILE_DEVICE_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_INPORT_PORT:
        return FILE_DEVICE_INPORT_PORTStr;
    case DeviceType::FILE_DEVICE_KEYBOARD:
        return FILE_DEVICE_KEYBOARDStr;
    case DeviceType::FILE_DEVICE_MAILSLOT:
        return FILE_DEVICE_MAILSLOTStr;
    case DeviceType::FILE_DEVICE_MIDI_IN:
        return FILE_DEVICE_MIDI_INStr;
    case DeviceType::FILE_DEVICE_MIDI_OUT:
        return FILE_DEVICE_MIDI_OUTStr;
    case DeviceType::FILE_DEVICE_MOUSE:
        return FILE_DEVICE_MOUSEStr;
    case DeviceType::FILE_DEVICE_MULTI_UNC_PROVIDER:
        return FILE_DEVICE_MULTI_UNC_PROVIDERStr;
    case DeviceType::FILE_DEVICE_NAMED_PIPE:
        return FILE_DEVICE_NAMED_PIPEStr;
    case DeviceType::FILE_DEVICE_NETWORK:
        return FILE_DEVICE_NETWORKStr;
    case DeviceType::FILE_DEVICE_NETWORK_BROWSER:
        return FILE_DEVICE_NETWORK_BROWSERStr;
    case DeviceType::FILE_DEVICE_NETWORK_FILE_SYSTEM:
        return FILE_DEVICE_NETWORK_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_NULL:
        return FILE_DEVICE_NULLStr;
    case DeviceType::FILE_DEVICE_PARALLEL_PORT:
        return FILE_DEVICE_PARALLEL_PORTStr;
    case DeviceType::FILE_DEVICE_PHYSICAL_NETCARD:
        return FILE_DEVICE_PHYSICAL_NETCARDStr;
    case DeviceType::FILE_DEVICE_PRINTER:
        return FILE_DEVICE_PRINTERStr;
    case DeviceType::FILE_DEVICE_SCANNER:
        return FILE_DEVICE_SCANNERStr;
    case DeviceType::FILE_DEVICE_SERIAL_MOUSE_PORT:
        return FILE_DEVICE_SERIAL_MOUSE_PORTStr;
    case DeviceType::FILE_DEVICE_SERIAL_PORT:
        return FILE_DEVICE_SERIAL_PORTStr;
    case DeviceType::FILE_DEVICE_SCREEN:
        return FILE_DEVICE_SCREENStr;
    case DeviceType::FILE_DEVICE_SOUND:
        return FILE_DEVICE_SOUNDStr;
    case DeviceType::FILE_DEVICE_STREAMS:
        return FILE_DEVICE_STREAMSStr;
    case DeviceType::FILE_DEVICE_TAPE:
        return FILE_DEVICE_TAPEStr;
    case DeviceType::FILE_DEVICE_TAPE_FILE_SYSTEM:
        return FILE_DEVICE_TAPE_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_TRANSPORT:
        return FILE_DEVICE_TRANSPORTStr;
    case DeviceType::FILE_DEVICE_UNKNOWN:
        return FILE_DEVICE_UNKNOWNStr;
    case DeviceType::FILE_DEVICE_VIDEO:
        return FILE_DEVICE_VIDEOStr;
    case DeviceType::FILE_DEVICE_VIRTUAL_DISK:
        return FILE_DEVICE_VIRTUAL_DISKStr;
    case DeviceType::FILE_DEVICE_WAVE_IN:
        return FILE_DEVICE_WAVE_INStr;
    case DeviceType::FILE_DEVICE_WAVE_OUT:
        return FILE_DEVICE_WAVE_OUTStr;
    case DeviceType::FILE_DEVICE_8042_PORT:
        return FILE_DEVICE_8042_PORTStr;
    case DeviceType::FILE_DEVICE_NETWORK_REDIRECTOR:
        return FILE_DEVICE_NETWORK_REDIRECTORStr;
    case DeviceType::FILE_DEVICE_BATTERY:
        return FILE_DEVICE_BATTERYStr;
    case DeviceType::FILE_DEVICE_BUS_EXTENDER:
        return FILE_DEVICE_BUS_EXTENDERStr;
    case DeviceType::FILE_DEVICE_MODEM:
        return FILE_DEVICE_MODEMStr;
    case DeviceType::FILE_DEVICE_VDM:
        return FILE_DEVICE_VDMStr;
    case DeviceType::FILE_DEVICE_MASS_STORAGE:
        return FILE_DEVICE_MASS_STORAGEStr;
    case DeviceType::FILE_DEVICE_SMB:
        return FILE_DEVICE_SMBStr;
    case DeviceType::FILE_DEVICE_KS:
        return FILE_DEVICE_KSStr;
    case DeviceType::FILE_DEVICE_CHANGER:
        return FILE_DEVICE_CHANGERStr;
    case DeviceType::FILE_DEVICE_SMARTCARD:
        return FILE_DEVICE_SMARTCARDStr;
    case DeviceType::FILE_DEVICE_ACPI:
        return FILE_DEVICE_ACPIStr;
    case DeviceType::FILE_DEVICE_DVD:
        return FILE_DEVICE_DVDStr;
    case DeviceType::FILE_DEVICE_FULLSCREEN_VIDEO:
        return FILE_DEVICE_FULLSCREEN_VIDEOStr;
    case DeviceType::FILE_DEVICE_DFS_FILE_SYSTEM:
        return FILE_DEVICE_DFS_FILE_SYSTEMStr;
    case DeviceType::FILE_DEVICE_DFS_VOLUME:
        return FILE_DEVICE_DFS_VOLUMEStr;
    case DeviceType::FILE_DEVICE_SERENUM:
        return FILE_DEVICE_SERENUMStr;
    case DeviceType::FILE_DEVICE_TERMSRV:
        return FILE_DEVICE_TERMSRVStr;
    case DeviceType::FILE_DEVICE_KSEC:
        return FILE_DEVICE_KSECStr;
    case DeviceType::FILE_DEVICE_FIPS:
        return FILE_DEVICE_FIPSStr;
    case DeviceType::FILE_DEVICE_INFINIBAND:
        return FILE_DEVICE_INFINIBANDStr;
    case DeviceType::FILE_DEVICE_VMBUS:
        return FILE_DEVICE_VMBUSStr;
    case DeviceType::FILE_DEVICE_CRYPT_PROVIDER:
        return FILE_DEVICE_CRYPT_PROVIDERStr;
    case DeviceType::FILE_DEVICE_WPD:
        return FILE_DEVICE_WPDStr;
    case DeviceType::FILE_DEVICE_BLUETOOTH:
        return FILE_DEVICE_BLUETOOTHStr;
    case DeviceType::FILE_DEVICE_MT_COMPOSITE:
        return FILE_DEVICE_MT_COMPOSITEStr;
    case DeviceType::FILE_DEVICE_MT_TRANSPORT:
        return FILE_DEVICE_MT_TRANSPORTStr;
    case DeviceType::FILE_DEVICE_BIOMETRIC:
        return FILE_DEVICE_BIOMETRICStr;
    case DeviceType::FILE_DEVICE_PMI:
        return FILE_DEVICE_PMIStr;
    }

    return FILE_DEVICE_UNKNOWNStr;
}

std::ostream& operator<<(std::ostream& os, DeviceType type) {
    os << to_string(type);
    return os;
}

} // namespace nt
} // namespace windows
} // namespace introvirt