#pragma once
#include <windows.h>
#include <winternl.h>
#include "../shared.hpp"
#include <system_error>
#include <random>
#include <deque>

extern "C" NTSYSAPI NTSTATUS NtOpenEvent(
  PHANDLE            EventHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS wrapperNtOpenEvent(
  PHANDLE            EventHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  uint32_t syscallidx,
  uintptr_t magic,
  void* commands
);

class SimpleRWInstance
{
  uint64_t _magic = 0;
  UNICODE_STRING _symname{};
  OBJECT_ATTRIBUTES _attr{};
  uint32_t _idx{};

public:
  void init()
  {
    _magic = std::random_device{}();

    RtlInitUnicodeString(&_symname, SYMLINK_NAME);
    HANDLE symhandle;
    InitializeObjectAttributes(
      &_attr,
      &_symname,
      OBJ_PERMANENT,
      NULL,
      NULL
    );

    _idx = *(uint32_t*)((char*)&NtOpenEvent + 4);

    HANDLE h;
    const auto status = wrapperNtOpenEvent(&h, FILE_READ_ACCESS, &_attr, _idx, k_magic_initial, (void*)_magic);

    if(status != ((NTSTATUS)0xC000A089L))
      throw std::runtime_error("Driver not running");
  }

  ~SimpleRWInstance()
  {
  }

  void execute_query(CmdVmOperations* ops, DWORD size)
  {
    ops->size = size;
    HANDLE h;
    wrapperNtOpenEvent(&h, FILE_READ_ACCESS, &_attr, _idx, _magic, ops);
  }
};

class RemoteProcess
{
  CmdVmOperations _cmdhead;

  std::deque<VmOperation> _ops;

public:
  RemoteProcess(DWORD pid)
  {
    _cmdhead.local_pid = GetCurrentProcessId();
    _cmdhead.remote_pid = pid;
  }

  void read(void* to, void* from, size_t size, VmOperationResult* result = nullptr)
  {
    _ops.push_back({ VmOperationRead, (uint32_t)size, result, to, from });
  }

  void write(void* to, void* from, size_t size, VmOperationResult* result = nullptr)
  {
    _ops.push_back({ VmOperationWrite, (uint32_t)size, result, from, to });
  }

  void get_peb(void** to)
  {
    _ops.push_back({ VmOperationGetRemotePeb, 0, nullptr, to, nullptr });
  }

  void run(SimpleRWInstance& srw)
  {
    if(!_ops.empty())
    {
      const auto mem_size = sizeof(_cmdhead) + (_ops.size() - 1) * sizeof(VmOperation);
      const auto mem = std::make_unique<BYTE[]>(mem_size);

      const auto ptr = (CmdVmOperations*)mem.get();

      *ptr = _cmdhead;
      for (auto i = 0u; i < _ops.size(); ++i)
        ptr->ops[i] = _ops[i];

      srw.execute_query(ptr, (DWORD)mem_size);
    }
  }
};