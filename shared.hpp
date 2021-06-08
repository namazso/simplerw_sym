#pragma once
#include <cstdint>

// generated with random.org guaranteed secure :))))
constexpr static uint64_t k_magic_initial = 0x293f819e4d70015a;

#define SYMLINK_NAME L"\\DosDevices\\NotADevice"

enum VmOperationType : uint32_t
{
  VmOperationRead,
  VmOperationWrite,
  VmOperationGetRemotePeb
};

struct VmOperationResult
{
  NTSTATUS status;
  uint32_t result_bytes;
};

struct VmOperation
{
  VmOperationType type;
  uint32_t size;
  VmOperationResult* status;
  void* local_address;
  void* remote_address;
};

struct CmdVmOperations
{
  uint32_t local_pid;
  uint32_t remote_pid;
  uint32_t size;

  VmOperation ops[1];
};
