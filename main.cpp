#include <ntifs.h>
#include <ntddk.h>
#include <cstdint>
#include <algorithm>
#include <intrin.h>
#include "shared.hpp"

typedef struct _OBJECT_SYMBOLIC_LINK
{
  /* 0x0000 */ union _LARGE_INTEGER CreationTime;
  union
  {
    /* 0x0008 */ struct _UNICODE_STRING LinkTarget;
    struct
    {
      /* 0x0008 */ void* Callback /* function */;
      /* 0x0010 */ void* CallbackContext;
    }; /* size: 0x0010 */
  }; /* size: 0x0010 */
  /* 0x0018 */ unsigned long DosDeviceDriveIndex;
  /* 0x001c */ unsigned long Flags;
  /* 0x0020 */ unsigned long AccessMask;
  /* 0x0024 */ long __PADDING__[1];
} OBJECT_SYMBOLIC_LINK, *POBJECT_SYMBOLIC_LINK; /* size: 0x0028 */

extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateSymbolicLinkObject(
  _Out_ PHANDLE LinkHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ PUNICODE_STRING LinkTarget
);

extern "C" NTSTATUS NTKERNELAPI MmCopyVirtualMemory(
  PEPROCESS SourceProcess,
  PVOID SourceAddress,
  PEPROCESS TargetProcess,
  PVOID TargetAddress,
  SIZE_T BufferSize,
  KPROCESSOR_MODE PreviousMode,
  PSIZE_T ReturnSize
);

extern "C" PPEB NTKERNELAPI PsGetProcessPeb(
  PEPROCESS Process
);

extern "C" PVOID NTKERNELAPI RtlPcToFileHeader(
  PVOID PcValue,
  PVOID *BaseOfImage
);

extern "C" NTSTATUS NTKERNELAPI ObReferenceObjectByName(
  PUNICODE_STRING ObjectName,
  ULONG Attributes,
  PACCESS_STATE AccessState,
  ACCESS_MASK DesiredAccess,
  POBJECT_TYPE ObjectType,
  KPROCESSOR_MODE AccessMode,
  PVOID ParseContext OPTIONAL,
  PVOID* Object
);

extern "C" extern POBJECT_TYPE *IoDeviceObjectType;

//void* get_trampoline(void* pe);

static NTSTATUS write_to_process(PEPROCESS target_process, PVOID target_address, PVOID source_address, SIZE_T size)
{
  if (intptr_t(target_address) <= 0)
    return STATUS_ACCESS_DENIED;

    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE state;

    __try
    {
      memcpy(target_address, source_address, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      status = STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&state);

    return status;
}

static uint64_t g_magic = k_magic_initial;

void handle_cmds(
  CmdVmOperations* cmd
)
{
  //if (true)
  {
    PEPROCESS local;

    auto status = PsLookupProcessByProcessId((HANDLE)(uintptr_t)cmd->local_pid, &local);

    if (NT_SUCCESS(status))
    {
      PEPROCESS remote;

      status = PsLookupProcessByProcessId((HANDLE)(uintptr_t)cmd->remote_pid, &remote);

      if (NT_SUCCESS(status))
      {
        const auto count = (cmd->size - sizeof(CmdVmOperations)) / sizeof(VmOperation) + 1;

        for (auto i = 0u; i < count; ++i)
        {
          const auto current = &cmd->ops[i];

          auto target_process = remote;
          auto target_address = current->remote_address;

          auto source_process = local;
          auto source_address = current->local_address;

          switch (current->type)
          {
          case VmOperationRead:
            std::swap(target_process, source_process);
            std::swap(target_address, source_address);
          case VmOperationWrite:
          {
            const auto size = current->size;

            const auto result_address = current->status;
            VmOperationResult result{};
            SIZE_T return_size = 0;

            result.status = MmCopyVirtualMemory(
              source_process, source_address,
              target_process, target_address,
              size, UserMode, &return_size
            );

            result.result_bytes = (uint32_t)return_size;

            write_to_process(local, result_address, &result, sizeof(result));
          }
          break;
          case VmOperationGetRemotePeb:
          {
            auto peb = PsGetProcessPeb(remote);
            SIZE_T return_size;

            write_to_process(local, source_address, &peb, sizeof(peb));
          }
          break;
          default:;
          }
        }

        ObDereferenceObject(remote);
      }

      ObDereferenceObject(local);
    }
  }

  return;// retval;
}

// example prototype:
//NTSTATUS MiResolveMemoryEvent(_OBJECT_SYMBOLIC_LINK *SymbolicLink, PVOID Context, PUNICODE_STRING OutObjectName, PVOID *OutObject);

NTSTATUS symlink_callback_handler(_OBJECT_SYMBOLIC_LINK *SymbolicLink, PVOID Context, PUNICODE_STRING OutObjectName, PVOID *OutObject)
{
  //__debugbreak();

  const auto begin = (uintptr_t*)_AddressOfReturnAddress();
  const auto end = ((uintptr_t*)((((uintptr_t)begin) | 0xFFF) + 1)) - 1;

  for(auto it = begin; it != end; ++it)
  {
    if(*it == g_magic)
    {
      const auto payload = *(it + 1);
      if(g_magic == k_magic_initial)
      {
        g_magic = payload;
      }
      else
      {
        handle_cmds((CmdVmOperations*)payload);
      }
      break;
    }
  }

  return STATUS_INCORRECT_ACCOUNT_TYPE;
}

void clear_traces(PDRIVER_OBJECT driver_object);

extern "C"
NTSTATUS EntryPoint()
{
  UNICODE_STRING bogus_device = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
  UNICODE_STRING symname = RTL_CONSTANT_STRING(SYMLINK_NAME);
  //IoCreateSymbolicLink(&symlink, &device);
  HANDLE symhandle;
  OBJECT_ATTRIBUTES attr;
  InitializeObjectAttributes(
    &attr,
    &symname,
    OBJ_PERMANENT,
    NULL,
    NULL
  );
  ZwCreateSymbolicLinkObject(
    &symhandle,
    FILE_ALL_ACCESS,
    &attr,
    &bogus_device
  );
  PVOID obj;
  ObReferenceObjectByHandle(
    symhandle,
    FILE_ALL_ACCESS,
    NULL,
    KernelMode,
    &obj,
    NULL
  );
  const auto symobj = (_OBJECT_SYMBOLIC_LINK*)obj;
  symobj->Flags |= 0x10;
  RtlFreeUnicodeString(&symobj->LinkTarget);
  symobj->Callback = (PVOID)&symlink_callback_handler;
  symobj->CallbackContext = nullptr; // unused but still
  ObDereferenceObject(obj);
  NtClose(symhandle);
}