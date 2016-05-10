/*
 * Copyright 2016 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <folly/portability/SysMman.h>

#ifdef _WIN32
#include <folly/portability/Windows.h>

static bool mmap_to_page_protection(int prot, DWORD& ret) {
  if (prot == PROT_NONE) {
    ret = PAGE_NOACCESS;
  } else if (prot == PROT_READ) {
    ret = PAGE_READONLY;
  } else if (prot == PROT_EXEC) {
    ret = PAGE_EXECUTE;
  } else if (prot == (PROT_READ | PROT_EXEC)) {
    ret = PAGE_EXECUTE_READ;
  } else if (prot == (PROT_READ | PROT_WRITE)) {
    ret = PAGE_READWRITE;
  } else if (prot == (PROT_READ | PROT_WRITE | PROT_EXEC)) {
    ret = PAGE_EXECUTE_READWRITE;
  } else {
    return false;
  }
  return true;
}

extern "C" {
int madvise(const void* addr, size_t len, int advise) {
  // We do nothing at all.
  // Could probably implement dontneed via VirtualAlloc
  // with the MEM_RESET and MEM_RESET_UNDO flags.
  return 0;
}

int mlock(const void* addr, size_t len) {
  if (!VirtualLock((void*)addr, len)) {
    return -1;
  }
  return 0;
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t off) {
  // Make sure it's something we support first.

  // No Anon shared.
  if ((flags & (MAP_ANONYMOUS | MAP_SHARED)) == (MAP_ANONYMOUS | MAP_SHARED)) {
    return MAP_FAILED;
  }
  // No private copy on write.
  if ((flags & MAP_PRIVATE) == MAP_PRIVATE && fd != -1) {
    return MAP_FAILED;
  }
  // Map isn't anon, must be file backed.
  if (!(flags & MAP_ANONYMOUS) && fd == -1) {
    return MAP_FAILED;
  }

  DWORD newProt;
  if (!mmap_to_page_protection(prot, newProt)) {
    return MAP_FAILED;
  }

  void* ret;
  if (!(flags & MAP_ANONYMOUS) || (flags & MAP_SHARED)) {
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!(flags & MAP_ANONYMOUS)) {
      h = (HANDLE)_get_osfhandle(fd);
    }

    HANDLE fmh = CreateFileMapping(
        h,
        nullptr,
        newProt | SEC_COMMIT | SEC_RESERVE,
        (DWORD)((length >> 32) & 0xFFFFFFFF),
        (DWORD)(length & 0xFFFFFFFF),
        nullptr);
    ret = MapViewOfFileEx(
        fmh,
        FILE_MAP_ALL_ACCESS,
        (DWORD)((off >> 32) & 0xFFFFFFFF),
        (DWORD)(off & 0xFFFFFFFF),
        0,
        addr);
    if (ret == nullptr) {
      ret = MAP_FAILED;
    }
    CloseHandle(fmh);
  } else {
    ret = VirtualAlloc(addr, length, MEM_COMMIT | MEM_RESERVE, newProt);
    if (ret == nullptr) {
      return MAP_FAILED;
    }
  }

  // TODO: Could technically implement MAP_POPULATE via PrefetchVirtualMemory
  //       Should also see about implementing MAP_NORESERVE
  return ret;
}

int mprotect(void* addr, size_t size, int prot) {
  DWORD newProt;
  if (!mmap_to_page_protection(prot, newProt)) {
    return -1;
  }

  DWORD oldProt;
  BOOL res = VirtualProtect(addr, size, newProt, &oldProt);
  if (!res) {
    return -1;
  }
  return 0;
}

int munlock(const void* addr, size_t length) {
  if (!VirtualUnlock((void*)addr, length)) {
    return -1;
  }
  return 0;
}

int munmap(void* addr, size_t length) {
  // Try to unmap it as a file, otherwise VirtualFree.
  if (!UnmapViewOfFile(addr)) {
    if (!VirtualFree(addr, length, MEM_RELEASE)) {
      return -1;
    }
    return 0;
  }
  return 0;
}
}
#endif
