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
#pragma once

#include "windows/common/TypeContainer.hh"
#include "windows/common/TypeOffsets.hh"

#include "base.hh"

namespace introvirt {
namespace windows {
namespace nt {
namespace structs {

#define MEMBER_STRUCT(Type, Name)                                                                  \
    structs::Type Name { container_, Member(*this, #Name) }
#define OPTIONAL_MEMBER_STRUCT(Type, Name)                                                         \
    structs::Type Name { container_, OptionalMember(*this, #Name) }
#define RECURSIVE_MEMBER_STRUCT(Type, Name)                                                        \
    structs::Type Name { container_, RecursiveMember(*this, #Name) }
#define MEMBER_STRUCT_MULTISZ(Type, Name, ...)                                                     \
    Type Name { container_, Member(*this, std::vector<std::string>{__VA_ARGS__}) }

#define BEGIN_NT_STRUCT_CONSTRUCTOR(Name)                                                          \
    class Name : public NTTypeOffsets {                                                            \
      public:                                                                                      \
        Name(const TypeContainer& container, size_t base_offset = 0)                               \
            : NTTypeOffsets(container, "_" #Name, base_offset) {

#define END_NT_STRUCT_CONSTRUCTOR(Name)                                                            \
    }                                                                                              \
                                                                                                   \
  public:                                                                                          \
    static constexpr const TypeID ID = TypeID::Name;

#define BEGIN_NT_STRUCT(Name)                                                                      \
    BEGIN_NT_STRUCT_CONSTRUCTOR(Name)                                                              \
    END_NT_STRUCT_CONSTRUCTOR(Name)

#define END_NT_STRUCT(Name)                                                                        \
    }                                                                                              \
    ;

class NTTypeOffsets : public TypeOffsets {
  public:
    NTTypeOffsets(const TypeContainer& container, const std::string& structure_name,
                  size_t base_offset)
        : TypeOffsets(container, container.pdb(), structure_name, base_offset),
          container_(container) {}

  protected:
    const TypeContainer& container_;
};

/*
 * Begin structures
 */
BEGIN_NT_STRUCT(EX_PUSH_LOCK)
MEMBER(Locked);
MEMBER(Value);
END_NT_STRUCT(NT_PUSH_LOCK)

BEGIN_NT_STRUCT(UNICODE_STRING)
MEMBER(Length);
MEMBER(MaximumLength);
MEMBER(Buffer);
END_NT_STRUCT(UNICODE_STRING)

BEGIN_NT_STRUCT(CLIENT_ID)
MEMBER(UniqueProcess);
MEMBER(UniqueThread);
END_NT_STRUCT(CLIENT_ID)

BEGIN_NT_STRUCT(CM_KEY_BODY)
MEMBER(KeyControlBlock);
MEMBER(ProcessID);
END_NT_STRUCT(CM_KEY_BODY)

BEGIN_NT_STRUCT(CONTEXT)
OPTIONAL_MEMBER(P1Home);
OPTIONAL_MEMBER(P2Home);
OPTIONAL_MEMBER(P3Home);
OPTIONAL_MEMBER(P4Home);
OPTIONAL_MEMBER(P5Home);
OPTIONAL_MEMBER(P6Home);
MEMBER(ContextFlags);

MEMBER_MULTISZ(Rax, "Rax", "Eax");
MEMBER_MULTISZ(Rcx, "Rcx", "Ecx");
MEMBER_MULTISZ(Rdx, "Rdx", "Edx");
MEMBER_MULTISZ(Rbx, "Rbx", "Ebx");
MEMBER_MULTISZ(Rsp, "Rsp", "Esp");
MEMBER_MULTISZ(Rbp, "Rbp", "Ebp");
MEMBER_MULTISZ(Rsi, "Rsi", "Esi");
MEMBER_MULTISZ(Rdi, "Rdi", "Edi");
OPTIONAL_MEMBER(R8);
OPTIONAL_MEMBER(R9);
OPTIONAL_MEMBER(R10);
OPTIONAL_MEMBER(R11);
OPTIONAL_MEMBER(R12);
OPTIONAL_MEMBER(R13);
OPTIONAL_MEMBER(R14);
OPTIONAL_MEMBER(R15);
MEMBER_MULTISZ(Rip, "Rip", "Eip");

MEMBER(SegCs);
MEMBER(SegDs);
MEMBER(SegEs);
MEMBER(SegFs);
MEMBER(SegGs);
MEMBER(SegSs);
MEMBER(EFlags);

MEMBER(Dr0);
MEMBER(Dr1);
MEMBER(Dr2);
MEMBER(Dr3);
MEMBER(Dr6);
MEMBER(Dr7);

OPTIONAL_MEMBER(MxCsr);
END_NT_STRUCT(CONTEXT)

BEGIN_NT_STRUCT(DEVICE_OBJECT)
MEMBER(DriverObject);
MEMBER(DeviceType);
END_NT_STRUCT(DEVICE_OBJECT)

BEGIN_NT_STRUCT(DRIVER_OBJECT)
MEMBER(DeviceObject);
MEMBER(DriverName);
MEMBER(MajorFunction);
END_NT_STRUCT(DRIVER_OBJECT)

BEGIN_NT_STRUCT(FILE_OBJECT)
MEMBER(DeviceObject);
MEMBER(FileName);
MEMBER(DeletePending);
MEMBER(DeleteAccess);
MEMBER(Flags);
MEMBER(SharedDelete);
END_NT_STRUCT(FILE_OBJECT)

BEGIN_NT_STRUCT_CONSTRUCTOR(HANDLE_TABLE_ENTRY)
if (unlikely(!ObjectPointerBits.exists() && !Value.exists())) {
    throw TypeInformationException(
        "Unable to find ObjectPointerBits or Value in HANDLE_TABLE_ENTRY");
}
if (unlikely(!GrantedAccessBits.exists() && !GrantedAccess.exists())) {
    throw TypeInformationException(
        "Unable to find GrantedAccessBits or GrantedAccess in HANDLE_TABLE_ENTRY");
}
END_NT_STRUCT_CONSTRUCTOR(HANDLE_TABLE_ENTRY)
// New style
OPTIONAL_MEMBER(ObjectPointerBits);
OPTIONAL_MEMBER(GrantedAccessBits);

// Old style
OPTIONAL_MEMBER(GrantedAccess);
OPTIONAL_MEMBER(Value);
END_NT_STRUCT(HANDLE_TABLE_ENTRY)

BEGIN_NT_STRUCT(HANDLE_TABLE_FREE_LIST)
MEMBER(HandleCount);
END_NT_STRUCT(HANDLE_TABLE_FREE_LIST)

BEGIN_NT_STRUCT_CONSTRUCTOR(HANDLE_TABLE)
if (!HandleCount.exists() && !FreeLists.exists()) {
    throw TypeInformationException("Missing HANDLE_TABLE::HandleCount/FreeLists");
}
END_NT_STRUCT_CONSTRUCTOR(HANDLE_TABLE)
MEMBER(TableCode);
MEMBER(NextHandleNeedingPool);
MEMBER(Flags);
MEMBER(UniqueProcessId);
MEMBER(QuotaProcess);
OPTIONAL_MEMBER(HandleCount);
OPTIONAL_MEMBER(FreeLists);
END_NT_STRUCT(HANDLE_TABLE)

BEGIN_NT_STRUCT(OBJECT_DIRECTORY)
MEMBER(HashBuckets);
END_NT_STRUCT(OBJECT_DIRECTORY)

BEGIN_NT_STRUCT(OBJECT_DIRECTORY_ENTRY)
MEMBER(Object);
MEMBER(ChainLink);
END_NT_STRUCT(OBJECT_DIRECTORY_ENTRY)

BEGIN_NT_STRUCT(OBJECT_HEADER_CREATOR_INFO)
MEMBER(CreatorUniqueProcess);
END_NT_STRUCT(OBJECT_HEADER_CREATOR_INFO)

BEGIN_NT_STRUCT(OBJECT_HEADER_PROCESS_INFO)
MEMBER(ExclusiveProcess);
END_NT_STRUCT(OBJECT_HEADER_PROCESS_INFO)

BEGIN_NT_STRUCT(OBJECT_HEADER_HANDLE_INFO)
END_NT_STRUCT(OBJECT_HEADER_HANDLE_INFO)

BEGIN_NT_STRUCT(OBJECT_HEADER_QUOTA_INFO)
END_NT_STRUCT(OBJECT_HEADER_QUOTA_INFO)

BEGIN_NT_STRUCT(OBJECT_HEADER_NAME_INFO)
MEMBER_STRUCT(UNICODE_STRING, Name);
END_NT_STRUCT(OBJECT_HEADER_NAME_INFO)

BEGIN_NT_STRUCT(OBJECT_HEADER)
OPTIONAL_MEMBER(NameInfoOffset);   // XP
OPTIONAL_MEMBER(HandleInfoOffset); // XP
OPTIONAL_MEMBER(QuotaInfoOffset);  // XP
OPTIONAL_MEMBER(Type);             // XP
OPTIONAL_MEMBER(InfoMask);         // 6.1+
OPTIONAL_MEMBER(TypeIndex);        // 6.1+
MEMBER(Flags);
MEMBER(Body);
END_NT_STRUCT(OBJECT_HEADER)

BEGIN_NT_STRUCT(DISPATCHER_HEADER)
MEMBER(Type);
MEMBER(Absolute);
MEMBER(Size);
MEMBER(Inserted);
MEMBER(SignalState);
END_NT_STRUCT(DISPATCHER_HEADER)

BEGIN_NT_STRUCT(EX_FAST_REF)
MEMBER(Object);
MEMBER(RefCnt);
MEMBER(Value);
END_NT_STRUCT(EX_FAST_REF)

BEGIN_NT_STRUCT(CONTROL_AREA)
MEMBER(Segment);
MEMBER_STRUCT(EX_FAST_REF, FilePointer);

// Flags
RECURSIVE_MEMBER(File);  // Set if a file is mapped in
RECURSIVE_MEMBER(Image); // Set if the file is a PE
END_NT_STRUCT(CONTROL_AREA)

BEGIN_NT_STRUCT(KAPC_STATE)
MEMBER(Process);
END_NT_STRUCT(KAPC_STATE)

BEGIN_NT_STRUCT(KPROCESS)
MEMBER(DirectoryTableBase);
OPTIONAL_MEMBER(UserDirectoryTableBase);
MEMBER(ThreadListHead);
MEMBER(ReadyListHead);
END_NT_STRUCT(KPROCESS)

BEGIN_NT_STRUCT(PS_PROTECTION)
RECURSIVE_MEMBER(Level);
END_NT_STRUCT(PS_PROTECTION)

BEGIN_NT_STRUCT(EPROCESS)
MEMBER(ImageFileName);
MEMBER(Peb);
MEMBER(ObjectTable);
MEMBER(UniqueProcessId);
MEMBER(InheritedFromUniqueProcessId);
MEMBER(Token);
MEMBER(Cookie);
MEMBER(SectionBaseAddress);
MEMBER(Session);
OPTIONAL_MEMBER_MULTISZ(Wow64Process, "Wow64Process", "WoW64Process");
MEMBER(ModifiedPageCount);
MEMBER(CreateTime);
OPTIONAL_RECURSIVE_MEMBER(
    RightChild); // Hack because VadRoot is a _RTL_AVL_TREE on 10 and _MM_AVL_TABLE on 7
MEMBER(VadRoot);
MEMBER(ActiveProcessLinks);
MEMBER(SessionProcessLinks);
MEMBER(Win32Process);

RECURSIVE_MEMBER(MinimumWorkingSetSize);
RECURSIVE_MEMBER(MaximumWorkingSetSize);

OPTIONAL_RECURSIVE_MEMBER(DisableDynamicCode);
OPTIONAL_RECURSIVE_MEMBER(DisableDynamicCodeAllowOptOut);

MEMBER(ThreadListHead);

MEMBER_STRUCT(KPROCESS, Pcb);

OPTIONAL_MEMBER(Protection); // Optional PS_PROTECTION structure

END_NT_STRUCT(EPROCESS)

BEGIN_NT_STRUCT(KTHREAD)
OPTIONAL_MEMBER(Process);
MEMBER(BasePriority);
MEMBER(Priority);
MEMBER(State);
MEMBER(Preempted);
MEMBER(Saturation);
MEMBER(Teb);
MEMBER(KernelApcDisable);
OPTIONAL_MEMBER(SpecialApcDisable);
MEMBER(PreviousMode);
MEMBER(IdealProcessor);
MEMBER(UserIdealProcessor);
MEMBER(Affinity);
MEMBER(UserAffinity);
MEMBER(InitialStack);
MEMBER(StackBase);
MEMBER(StackLimit);
MEMBER(KernelStack);

MEMBER_STRUCT(KAPC_STATE, ApcState);
END_NT_STRUCT(KTHREAD)

BEGIN_NT_STRUCT_CONSTRUCTOR(ETHREAD)
if (!ThreadsProcess.exists()) {
    // Grab it from KTHREAD instead
    // ThreadsProcess = Tcb.Process;
    ThreadsProcess = Tcb.Process;
    if (!Tcb.Process.exists()) {
        // Neither one has it??
        throw TypeInformationException("Could not find member ThreadsProcess");
    }
}
END_NT_STRUCT_CONSTRUCTOR(ETHREAD)
MEMBER(CreateTime);
MEMBER_STRUCT(CLIENT_ID, Cid);
OPTIONAL_MEMBER(ThreadsProcess);
MEMBER(Win32StartAddress);
MEMBER(CrossThreadFlags);
MEMBER(ThreadListEntry);

MEMBER_STRUCT(KTHREAD, Tcb);
END_NT_STRUCT(ETHREAD)

BEGIN_NT_STRUCT(KPRCB)
MEMBER(CurrentThread);
MEMBER(IdleThread);
MEMBER(NextThread);
OPTIONAL_MEMBER(ShadowFlags);
OPTIONAL_MEMBER(KernelDirectoryTableBase);
END_NT_STRUCT(KPRCB)

BEGIN_NT_STRUCT(KPCR)
MEMBER_MULTISZ(Self, "Self", "SelfPcr");
MEMBER(Irql);
MEMBER_STRUCT_MULTISZ(KPRCB, Prcb, "PrcbData", "Prcb");
END_NT_STRUCT(KPCR)

BEGIN_NT_STRUCT(IO_STACK_LOCATION)
MEMBER(MajorFunction);
MEMBER(MinorFunction);
END_NT_STRUCT(IO_STACK_LOCATION)

BEGIN_NT_STRUCT(IO_STATUS_BLOCK)
MEMBER(Status);
MEMBER(Pointer);
MEMBER(Information);
END_NT_STRUCT(IO_STATUS_BLOCK)

BEGIN_NT_STRUCT(IRP)
MEMBER(Type);
MEMBER(Size);
MEMBER(CurrentLocation);
RECURSIVE_MEMBER(CurrentStackLocation);
MEMBER(IoStatus);
RECURSIVE_MEMBER(SystemBuffer);
END_NT_STRUCT(IRP)

BEGIN_NT_STRUCT(LDR_DATA_TABLE_ENTRY)
MEMBER(DllBase);
MEMBER(EntryPoint);
MEMBER(SizeOfImage);
MEMBER(FullDllName);
MEMBER(BaseDllName);
MEMBER(InLoadOrderLinks);
END_NT_STRUCT(LDR_DATA_TABLE_ENTRY)

BEGIN_NT_STRUCT(MMVAD_SHORT)
OPTIONAL_RECURSIVE_MEMBER(VadType);         // Vista+
OPTIONAL_RECURSIVE_MEMBER(ImageMap);        // XP
OPTIONAL_RECURSIVE_MEMBER(PhysicalMapping); // XP

RECURSIVE_MEMBER(PrivateMemory);
RECURSIVE_MEMBER(Protection);
RECURSIVE_MEMBER(CommitCharge);
RECURSIVE_MEMBER(MemCommit);

MEMBER(StartingVpn);
MEMBER(EndingVpn);
RECURSIVE_MEMBER_MULTISZ(LeftChild, "LeftChild", "Left");
RECURSIVE_MEMBER_MULTISZ(RightChild, "RightChild", "Right");

// These three were added at some point (Win10?)
// A single byte that you left-shift 32-bits and OR with the regular field
OPTIONAL_MEMBER(StartingVpnHigh);
OPTIONAL_MEMBER(EndingVpnHigh);
OPTIONAL_MEMBER(CommitChargeHigh);
RECURSIVE_MEMBER_STRUCT(EX_PUSH_LOCK, PushLock);
END_NT_STRUCT(MMVAD_SHORT)

BEGIN_NT_STRUCT(MMVAD)
OPTIONAL_MEMBER(Subsection);  // Vista+
OPTIONAL_MEMBER(ControlArea); // XP
MEMBER(FirstPrototypePte);
MEMBER(LastContiguousPte);
RECURSIVE_MEMBER_STRUCT(EX_PUSH_LOCK, PushLock);
END_NT_STRUCT(MMVAD)

BEGIN_NT_STRUCT(SUBSECTION)
MEMBER(ControlArea);
END_NT_STRUCT(SUBSECTION)

BEGIN_NT_STRUCT(MM_SESSION_SPACE)
MEMBER(SessionId);
MEMBER(ProcessList);
OPTIONAL_MEMBER(PoolTags);
END_NT_STRUCT(MM_SESSION_SPACE)

BEGIN_NT_STRUCT(PEB)
MEMBER(ImageBaseAddress);
MEMBER(Ldr);
MEMBER(ProcessParameters);
MEMBER(BeingDebugged);

MEMBER(OSMajorVersion);
MEMBER(OSMinorVersion);
MEMBER(OSBuildNumber);
MEMBER(OSCSDVersion);
MEMBER(OSPlatformId);
MEMBER(NumberOfProcessors);
END_NT_STRUCT(PEB)

BEGIN_NT_STRUCT(PEB32)
MEMBER(ImageBaseAddress);
MEMBER(Ldr);
MEMBER(ProcessParameters);
MEMBER(BeingDebugged);

MEMBER(OSMajorVersion);
MEMBER(OSMinorVersion);
MEMBER(OSBuildNumber);
MEMBER(OSCSDVersion);
MEMBER(OSPlatformId);
MEMBER(NumberOfProcessors);
END_NT_STRUCT(PEB32)

BEGIN_NT_STRUCT(PEB_LDR_DATA)
MEMBER(Initialized);
MEMBER(InLoadOrderModuleList);
END_NT_STRUCT(PEB_LDR_DATA)

BEGIN_NT_STRUCT(PORT_MESSAGE)
RECURSIVE_MEMBER(DataLength);
RECURSIVE_MEMBER(TotalLength);
RECURSIVE_MEMBER(Type);
RECURSIVE_MEMBER(DataInfoOffset);
MEMBER_STRUCT(CLIENT_ID, ClientId);
MEMBER(MessageId);
MEMBER(CallbackId);
END_NT_STRUCT(PORT_MESSAGE)

BEGIN_NT_STRUCT(RTL_USER_PROCESS_PARAMETERS)
MEMBER(CommandLine);
MEMBER(ImagePathName);
MEMBER(WindowTitle);
MEMBER(Environment);
END_NT_STRUCT(RTL_USER_PROCESS_PARAMETERS)

BEGIN_NT_STRUCT(SECTION)
MEMBER(StartingVpn);
MEMBER(EndingVpn);
RECURSIVE_MEMBER(ControlArea);
RECURSIVE_MEMBER(FileObject);
MEMBER(SizeOfSection);
END_NT_STRUCT(SECTION)

BEGIN_NT_STRUCT(SECTION_OBJECT)
MEMBER(StartingVa);
MEMBER(EndingVa);
MEMBER(Segment);
END_NT_STRUCT(SECTION_OBJECT)

BEGIN_NT_STRUCT(SEGMENT)
MEMBER(ControlArea);
MEMBER(FirstMappedVa);
MEMBER(SizeOfSegment);
END_NT_STRUCT(SEGMENT)

BEGIN_NT_STRUCT(SEGMENT_OBJECT)
MEMBER(ControlArea);
MEMBER(BaseAddress);
MEMBER(SizeOfSegment);
END_NT_STRUCT(SEGMENT_OBJECT)

BEGIN_NT_STRUCT(SID_IDENTIFIER_AUTHORITY)
MEMBER(Value);
END_NT_STRUCT(SID_IDENTIFIER_AUTHORITY)

BEGIN_NT_STRUCT(SID)
MEMBER(Revision);
MEMBER(SubAuthorityCount);
MEMBER_STRUCT(SID_IDENTIFIER_AUTHORITY, IdentifierAuthority);
MEMBER(SubAuthority);
END_NT_STRUCT(SID)

BEGIN_NT_STRUCT(SID_AND_ATTRIBUTES)
MEMBER(Sid);
MEMBER(Attributes);
END_NT_STRUCT(SID_AND_ATTRIBUTES)

BEGIN_NT_STRUCT(NT_TIB)
MEMBER(StackLimit);
MEMBER(StackBase);
END_NT_STRUCT(NT_TIB)

BEGIN_NT_STRUCT(TEB)
MEMBER_STRUCT(NT_TIB, NtTib);
MEMBER_STRUCT(CLIENT_ID, ClientId);
MEMBER(LastErrorValue);
MEMBER(LastStatusValue);
END_NT_STRUCT(TEB)

BEGIN_NT_STRUCT(OBJECT_SYMBOLIC_LINK)
MEMBER(LinkTarget);
OPTIONAL_MEMBER(Flags);
OPTIONAL_MEMBER(AccessMask); // Seen in Win10
END_NT_STRUCT(OBJECT_SYMBOLIC_LINK)

BEGIN_NT_STRUCT(OBJECT_TYPE)
MEMBER(Name);
MEMBER(TotalNumberOfObjects);
MEMBER(TotalNumberOfHandles);
MEMBER(HighWaterNumberOfObjects);
MEMBER(HighWaterNumberOfHandles);
MEMBER(Key);
MEMBER(Index);
END_NT_STRUCT(OBJECT_TYPE)

BEGIN_NT_STRUCT(SEP_TOKEN_PRIVILEGES)
MEMBER(Present);
MEMBER(Enabled);
MEMBER(EnabledByDefault);
END_NT_STRUCT(SEP_TOKEN_PRIVILEGES)

BEGIN_NT_STRUCT(TOKEN)
MEMBER(PrimaryGroup);
MEMBER(UserAndGroupCount);
MEMBER(UserAndGroups);
MEMBER(Privileges);
END_NT_STRUCT(TOKEN)

BEGIN_NT_STRUCT(CM_NAME_CONTROL_BLOCK)
RECURSIVE_MEMBER(Compressed);
RECURSIVE_MEMBER(NameLength);
RECURSIVE_MEMBER(Name);
END_NT_STRUCT(CM_NAME_CONTROL_BLOCK)

BEGIN_NT_STRUCT(CM_KEY_CONTROL_BLOCK)
MEMBER(NameBlock);
MEMBER(KeyHive);
RECURSIVE_MEMBER(Flags);
RECURSIVE_MEMBER(ExtFlags);
MEMBER(ParentKcb);
END_NT_STRUCT(CM_KEY_CONTROL_BLOCK)

BEGIN_NT_STRUCT(CM_KEY_INDEX)
MEMBER(Signature);
MEMBER(Count);
MEMBER(List);
END_NT_STRUCT(CM_KEY_INDEX)

BEGIN_NT_STRUCT(CHILD_LIST)
MEMBER(Count);
MEMBER(List);
END_NT_STRUCT(CHILD_LIST)

BEGIN_NT_STRUCT(CM_KEY_NODE)
MEMBER(Signature);
MEMBER(NameLength);
MEMBER(Name);
MEMBER(SubKeyCounts);
MEMBER(Flags);
RECURSIVE_MEMBER(SubKeyLists);
MEMBER_STRUCT(CHILD_LIST, ValueList);
END_NT_STRUCT(CM_KEY_NODE)

BEGIN_NT_STRUCT(CM_KEY_VALUE)
MEMBER(Signature);
MEMBER(NameLength);
MEMBER(Name);
MEMBER(Flags);
MEMBER(DataLength);
MEMBER(Data);
MEMBER(Type);
END_NT_STRUCT(CM_KEY_VALUE)

BEGIN_NT_STRUCT(HBASE_BLOCK)
MEMBER(Signature);
MEMBER(FileName);
MEMBER(RootCell);
MEMBER(Length);
MEMBER(TimeStamp);
END_NT_STRUCT(HBASE_BLOCK)

BEGIN_NT_STRUCT(LIST_ENTRY)
MEMBER(Flink);
MEMBER(Blink);
END_NT_STRUCT(LIST_ENTRY)

BEGIN_NT_STRUCT(HHIVE)
MEMBER(Signature);
MEMBER(BaseBlock);
MEMBER(HiveFlags);
MEMBER(Storage);
END_NT_STRUCT(HHIVE)

BEGIN_NT_STRUCT(CMHIVE)
MEMBER_STRUCT(HHIVE, Hive);
MEMBER_STRUCT(LIST_ENTRY, HiveList);
MEMBER_STRUCT(UNICODE_STRING, FileFullPath);
MEMBER_STRUCT(UNICODE_STRING, FileUserName);
OPTIONAL_MEMBER(HiveRootPath);
END_NT_STRUCT(CMHIVE)

BEGIN_NT_STRUCT(DUAL)
MEMBER(Map);
END_NT_STRUCT(DUAL)

BEGIN_NT_STRUCT(HMAP_ENTRY)
OPTIONAL_MEMBER(BlockAddress);        // Pre Win10
OPTIONAL_MEMBER(PermanentBinAddress); // Win10+
END_NT_STRUCT(HMAP_ENTRY)

BEGIN_NT_STRUCT(SECTION_IMAGE_INFORMATION)
MEMBER(TransferAddress);
MEMBER(ZeroBits);
MEMBER(MaximumStackSize);
MEMBER(CommittedStackSize);
MEMBER(SubSystemType);
END_NT_STRUCT(SECTION_IMAGE_INFORMATION)

BEGIN_NT_STRUCT(MMPTE_HARDWARE)
MEMBER(Valid);
MEMBER(PageFrameNumber);
END_NT_STRUCT(MMPTE_HARDWARE)

BEGIN_NT_STRUCT(MMPTE_SOFTWARE)
MEMBER(Valid);
MEMBER(PageFileHigh);
MEMBER(Protection);
END_NT_STRUCT(MMPTE_SOFTWARE)

BEGIN_NT_STRUCT(MMPTE_TRANSITION)
MEMBER(Valid);
MEMBER(Prototype);
MEMBER(Transition);
MEMBER(PageFrameNumber);
MEMBER(Protection);
END_NT_STRUCT(MMPTE_TRANSITION)

BEGIN_NT_STRUCT(MMPTE_PROTOTYPE)
MEMBER(Valid);
MEMBER(Prototype);
OPTIONAL_MEMBER(SwizzleBit);
MEMBER(ProtoAddress);
MEMBER(Protection);
END_NT_STRUCT(MMPTE_PROTOTYPE)

BEGIN_NT_STRUCT(MI_SYSTEM_INFORMATION)
OPTIONAL_RECURSIVE_MEMBER(InvalidPteMask);
END_NT_STRUCT(MI_SYSTEM_INFORMATION)

} // namespace structs
} // namespace nt
} // namespace windows
} // namespace introvirt
