/*
 * Copyright 2014-2020 Real Logic Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined(__linux__)
#define _BSD_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "aeron_platform.h"
#include "aeron_error.h"
#include "aeron_fileutil.h"

static void aeron_to_hex(char *str, const uint8_t *buf, int len)
{
    int i;
    for (i = 0; i < len; i += 1)
    {
        sprintf(str + 2 * i, "%02X", buf[i]);
    }
}

static void aeron_get_file_mapping_name(char *file_mapping_name, aeron_image_os_ipc_t *os_ipc)
{
    uint64_t buffer[2];
    char id_str[sizeof(buffer) * 2 + 1];
    buffer[0] = os_ipc->buffer_id;
    buffer[1] = os_ipc->process_id;
    aeron_to_hex(id_str, (uint8_t*)buffer, sizeof(buffer));
    sprintf(file_mapping_name, "file-mapping-aeron-%s",id_str);
}

#if defined(AERON_COMPILER_MSVC)
#define _CRT_RAND_S
#include <WinSock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <process.h>

#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_FAILED ((void*)-1)

#define MAP_SHARED 0x01
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IROTH 0
#define S_IWOTH 0
#define S_IRWXU 0
#define S_IRWXG 0
#define S_IRWXO 0

static int aeron_mmap(aeron_mapped_file_t *mapping, int fd, uint64_t offset, bool read_only)
{
    HANDLE hmap = CreateFileMapping((HANDLE)_get_osfhandle(fd), 0, PAGE_READWRITE, 0, 0, 0);

    if (!hmap)
    {
        aeron_set_err_from_last_err_code("CreateFileMapping");
        close(fd);
        return -1;
    }

    if (read_only)
    {
        mapping->addr = MapViewOfFileEx(hmap, FILE_MAP_READ, 0, (DWORD)offset, mapping->length, NULL);
    }
    else
    {
        mapping->addr = MapViewOfFileEx(hmap, FILE_MAP_WRITE, 0, (DWORD)offset, mapping->length, NULL);
    }

    if (!CloseHandle(hmap))
    {
        fprintf(stderr, "unable to close file mapping handle when aeron_mmap\n");
    }

    if (!mapping->addr)
    {
        mapping->addr = MAP_FAILED;
    }

    close(fd);

    return MAP_FAILED == mapping->addr ? -1 : 0;
}

static int aeron_mmap_anonymous(aeron_mapped_file_t *mapping, aeron_image_os_ipc_t *os_ipc, uint64_t offset, bool read_only, bool creating_new)
{
    char file_mapping_name[128];
    aeron_get_file_mapping_name(file_mapping_name, os_ipc);
    uint64_t length = os_ipc->buffer_length;
    HANDLE hmap = 0;
    if (creating_new)
    {
        hmap = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, (DWORD)(length >> 32), (DWORD)(length & UINT32_MAX), file_mapping_name);
    }
    else
    {
        hmap = OpenFileMappingA(SECTION_MAP_WRITE | SECTION_MAP_READ, FALSE, file_mapping_name);
    }

    if (!hmap)
    {
        aeron_set_err_from_last_err_code("aeron_mmap_anonymous %s", file_mapping_name);
        return -1;
    }

    if (read_only)
    {
        mapping->addr = MapViewOfFileEx(hmap, SECTION_MAP_READ, 0, (DWORD)offset, (SIZE_T)length, NULL);
    }
    else
    {
        mapping->addr = MapViewOfFileEx(hmap, SECTION_MAP_WRITE  | SECTION_MAP_READ, 0, (DWORD)offset, (SIZE_T)length, NULL);
    }

    if (!mapping->addr)
    {
        mapping->addr = MAP_FAILED;
    }
    else
    {
        mapping->length = (size_t)length;
    }

    if (!creating_new || MAP_FAILED == mapping->addr)
    {
        if (!CloseHandle(hmap))
        {
            fprintf(stderr, "unable to close file mapping handle when aeron_mmap_anonymous\n");
        }
    }
    else
    {
        os_ipc->os_handle = (int64_t)hmap;
    }

    return MAP_FAILED == mapping->addr ? -1 : 0;
}

int aeron_unmap(aeron_mapped_file_t *mapped_file)
{
    if (NULL != mapped_file->addr)
    {
        int result = UnmapViewOfFile(mapped_file->addr) ? 0 : -1;
        mapped_file->addr = NULL;
        return result;
    }

    return 0;
}

uint64_t aeron_usable_fs_space(const char *path)
{
    ULARGE_INTEGER lpAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes;

    if (!GetDiskFreeSpaceExA(
        path,
        &lpAvailableToCaller,
        &lpTotalNumberOfBytes,
        &lpTotalNumberOfFreeBytes))
    {
        return 0;
    }

    return (uint64_t)lpAvailableToCaller.QuadPart;
}

int aeron_create_file(const char* path)
{
    int fd;
    int error = _sopen_s(&fd, path, _O_RDWR | _O_CREAT | _O_EXCL, _SH_DENYNO, _S_IREAD | _S_IWRITE);

    if (error != NO_ERROR)
    {
        return -1;
    }

    return fd;
}

BOOL IsDots(const WCHAR *str)
{
    if (wcscmp(str, L".") && wcscmp(str, L".."))
        return FALSE;
    return TRUE;
}

static BOOL DeleteDirectory(const WCHAR *sPath)
{
    HANDLE hFind; // file handle
    WIN32_FIND_DATAW FindFileData;

    WCHAR DirPath[AERON_MAX_PATH];
    WCHAR FileName[AERON_MAX_PATH];

    wcscpy(DirPath, sPath);
    wcscat(DirPath, L"\\*"); // searching all files
    wcscpy(FileName, sPath);
    wcscat(FileName, L"\\");

    hFind = FindFirstFileW(DirPath, &FindFileData); // find the first file
    if (hFind == INVALID_HANDLE_VALUE)
        return FALSE;
    wcscpy(DirPath, FileName);

    bool bSearch = true;
    while (bSearch)
    { // until we finds an entry
        if (FindNextFileW(hFind, &FindFileData))
        {
            if (IsDots(FindFileData.cFileName))
                continue;
            wcscat(FileName, FindFileData.cFileName);
            if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {

                // we have found a directory, recurse
                if (!DeleteDirectory(FileName))
                {
                    FindClose(hFind);
                    return FALSE; // directory couldn't be deleted
                }
                RemoveDirectoryW(FileName); // remove the empty directory
                wcscpy(FileName, DirPath);
            }
            else
            {
                if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                    _wchmod(FileName, _S_IWRITE); // change read-only file mode
                if (!DeleteFileW(FileName))
                { // delete the file
                    FindClose(hFind);
                    return FALSE;
                }
                wcscpy(FileName, DirPath);
            }
        }
        else
        {
            if (GetLastError() == ERROR_NO_MORE_FILES) // no more files there
                bSearch = false;
            else
            {
                // some error occured, close the handle and return FALSE
                FindClose(hFind);
                return FALSE;
            }
        }
    }
    FindClose(hFind); // closing file handle

    return RemoveDirectoryW(sPath); // remove the empty directory
}

int aeron_delete_directory(const char *dir)
{
    wchar_t ws[AERON_MAX_PATH];
    swprintf(ws, AERON_MAX_PATH, L"%hs", dir);
    if (DeleteDirectory(ws) == FALSE)
    {
        return -1;
    }
    return 0;
}

int aeron_is_directory(const char* path)
{
    const DWORD attributes = GetFileAttributes(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

#else
#include <unistd.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <ftw.h>
#include <stdio.h>

static int aeron_mmap(aeron_mapped_file_t *mapping, int fd, off_t offset, bool read_only)
{
    if (read_only)
    {
        mapping->addr = mmap(NULL, mapping->length, PROT_READ, MAP_SHARED, fd, offset);
    }
    else
    {
        mapping->addr = mmap(NULL, mapping->length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    }
    close(fd);

    return MAP_FAILED == mapping->addr ? -1 : 0;
}


static int aeron_mmap_anonymous(aeron_mapped_file_t *mapping, aeron_image_os_ipc_t *os_ipc, uint64_t offset, bool read_only, bool creating_new)
{
    uint64_t length = os_ipc->buffer_length;
    int fd = -1;
    if (creating_new)
    {
        char file_mapping_name[128];
        aeron_get_file_mapping_name(file_mapping_name, os_ipc);
        fd = memfd_create(file_mapping_name, 0);
        if (fd < 0)
        {
            aeron_set_err_from_last_err_code("aeron_mmap_anonymous %s", file_mapping_name);
            return -1;
        }
    }
    else
    {
        fd = (int)os_ipc->os_handle;
    }
    if (read_only)
    {
        mapping->addr = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, offset);
    }
    else
    {
        mapping->addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    }
    if (creating_new && MAP_FAILED != mapping->addr)
    {
        os_ipc->os_handle = fd;
    }
    else
    {
        close(fd);
    }

    return MAP_FAILED == mapping->addr ? -1 : 0;
}

int aeron_unmap(aeron_mapped_file_t *mapped_file)
{
    if (NULL != mapped_file->addr)
    {
        return munmap(mapped_file->addr, mapped_file->length);
    }

    return 0;
}

static int unlink_func(const char *path, const struct stat *sb, int type_flag, struct FTW *ftw)
{
    if (remove(path) != 0)
    {
        aeron_set_err_from_last_err_code("could not remove %s", path);
    }

    return 0;
}

int aeron_delete_directory(const char *dirname)
{
    return nftw(dirname, unlink_func, 64, FTW_DEPTH | FTW_PHYS);
}

int aeron_is_directory(const char* dirname)
{
    struct stat sb;
    return stat(dirname, &sb) == 0 && S_ISDIR(sb.st_mode);
}

uint64_t aeron_usable_fs_space(const char *path)
{
    struct statvfs vfs;
    uint64_t result = 0;

    if (statvfs(path, &vfs) == 0)
    {
        result = vfs.f_bsize * vfs.f_bavail;
    }

    return result;
}

int aeron_create_file(const char* path)
{
    return open(path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
}
#endif

int64_t aeron_file_length(const char *filename)
{
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA info;

    if (GetFileAttributesExA(filename, GetFileExInfoStandard, &info) == 0)
    {
        return -1;
    }

    return ((int64_t)info.nFileSizeHigh << 32) | (info.nFileSizeLow);
#else
    struct stat stat_info;

    if (stat(filename, &stat_info) < 0)
    {
        return -1;
    }

    return stat_info.st_size;
#endif
}

int aeron_unlink(const char *path)
{
#ifdef _WIN32
    return _unlink(path);
#else
    return unlink(path);
#endif
}

int64_t aeron_get_pid()
{
    return getpid();
}

int aeron_ftruncate(int fd, uint64_t length)
{
#ifdef _WIN32
    HANDLE fh = (HANDLE)_get_osfhandle(fd);

    if (SetFilePointer(fh, (LONG)(length & UINT32_MAX), 0, FILE_BEGIN) == 0)
    {
        return -1;
    }

    if (SetEndOfFile(fh) == 0)
    {
        return -1;
    }

    return 0;
#else
    return ftruncate(fd, length);
#endif
}

int aeron_mkdir(const char *path, int permission)
{
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, permission);
#endif
}

size_t aeron_get_page_size()
{
#ifdef _WIN32
    SYSTEM_INFO sinfo;

    GetSystemInfo(&sinfo);
    return (size_t)sinfo.dwPageSize;
#else
    return (size_t)getpagesize();
#endif
}

static void aeron_touch_pages(volatile uint8_t *base, size_t length, size_t page_size)
{
    for (size_t i = 0; i < length; i += page_size)
    {
        volatile uint8_t *first_page_byte = base + i;
        *first_page_byte = 0;
    }
}

int aeron_map_new_file(aeron_mapped_file_t *mapped_file, const char *path, bool fill_with_zeroes)
{
    int fd, result = -1;

    if ((fd = aeron_create_file(path)) >= 0)
    {
        if (aeron_ftruncate(fd, (off_t)mapped_file->length) >= 0)
        {
            if (aeron_mmap(mapped_file, fd, 0, false) == 0)
            {
                if (fill_with_zeroes)
                {
                    aeron_touch_pages(mapped_file->addr, mapped_file->length, aeron_get_page_size());
                }

                result = 0;
            }
            else
            {
                aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
            }
        }
        else
        {
            aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
        }
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }

    return result;
}

int aeron_map_existing_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool read_only)
{
    int fd, result = -1;

    if ((fd = open(path, O_RDWR)) >= 0)
    {
        if (size == 0)
        {
            struct stat sb;
            if (fstat(fd, &sb) == 0)
            {
                size = sb.st_size;
            }
        }
        if (size > 0)
        {
            mapped_file->length = size;

            if (aeron_mmap(mapped_file, fd, offset, read_only) == 0)
            {
                result = 0;
            }
            else
            {
                aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
            }
        }
        else
        {
            aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
        }
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }

    return result;
}

int aeron_map_new_os_ipc(aeron_mapped_file_t *mapped_file, aeron_image_os_ipc_t *os_ipc, uint64_t length, bool fill_with_zeroes)
{
    int result = -1;
    os_ipc->buffer_length = length;
    mapped_file->addr = NULL;
    mapped_file->length = 0;

    if (aeron_mmap_anonymous(mapped_file, os_ipc, 0, false, true) == 0)
    {
        if (fill_with_zeroes)
        {
            aeron_touch_pages(mapped_file->addr, mapped_file->length, aeron_get_page_size());
        }

        result = 0;
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }
    return result;
}

int aeron_map_existing_os_ipc(aeron_mapped_file_t *mapped_file, const aeron_image_os_ipc_t *os_ipc, bool read_only)
{
    aeron_image_os_ipc_t os_ipc_copied = *os_ipc;
    int result = -1;
    mapped_file->addr = NULL;
    mapped_file->length = 0;

    if (aeron_mmap_anonymous(mapped_file, &os_ipc_copied, 0, read_only, false) == 0)
    {
        result = 0;
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }
    return result;
}

int aeron_close_os_ipc(aeron_image_os_ipc_t *os_ipc)
{
#ifdef _WIN32
    HANDLE *handle = (HANDLE)os_ipc->os_handle;
    os_ipc->os_handle = -1;
    if (handle != 0 && handle != INVALID_HANDLE_VALUE)
    {
        if (!CloseHandle(handle))
        {
            return -1;
        }
    }
#else
    int fd = (int)os_ipc->os_handle;
    os_ipc->os_handle = -1;
    if (fd >= 0)
    {
        close(fd);
    }
#endif
    return 0;
}

uint64_t aeron_usable_fs_space_disabled(const char *path)
{
    return UINT64_MAX;
}

void aeron_os_ipc_location(
    aeron_image_os_ipc_t *os_ipc,
    int64_t buffer_id)
{
    os_ipc->buffer_length = 0;
    os_ipc->buffer_id = buffer_id;
    os_ipc->process_id = aeron_get_pid();
    os_ipc->os_handle = -1;
}

const char *aeron_tmp_dir()
{
#if defined(_MSC_VER)
    static char buff[MAX_PATH + 1];

    if (GetTempPath(MAX_PATH, &buff[0]) > 0)
    {
        return buff;
    }

    return NULL;
#else
    const char *dir = "/tmp";

    if (getenv("TMPDIR"))
    {
        dir = getenv("TMPDIR");
    }

    return dir;
#endif
}

static const char *aeron_username()
{
    const char *username = getenv("USER");
#if (_MSC_VER)
    if (NULL == username)
    {
        username = getenv("USERNAME");
        if (NULL == username)
        {
             username = "default";
        }
    }
#else
    if (NULL == username)
    {
        username = "default";
    }
#endif
    return username;
}

bool has_file_separator_at_end(const char *path)
{
#if defined(_MSC_VER)
    const char last = path[strlen(path) - 1];
    return last == '\\' || last == '/';
#else
    return path[strlen(path) - 1] == '/';
#endif
}

void aeron_default_dir(char *aeron_dir, size_t length)
{

#if defined(__linux__)
    snprintf(aeron_dir, length, "/dev/shm/aeron-%s", aeron_username());
#elif defined(_MSC_VER)
    snprintf(aeron_dir, length, "%s%saeron-%s", aeron_tmp_dir(), has_file_separator_at_end(aeron_tmp_dir()) ? "" : "\\", aeron_username());
#else
    snprintf(aeron_dir, length, "%s%saeron-%s", aeron_tmp_dir(), has_file_separator_at_end(aeron_tmp_dir()) ? "" : "/", aeron_username());
#endif
}

#if !defined(AERON_CPP_CLIENT)

#include "aeron_map_raw_log.h"

int aeron_map_raw_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    aeron_image_os_ipc_t *os_ipc,
    bool use_sparse_files,
    uint64_t term_length,
    uint64_t page_size)
{
    int result = -1;
    uint64_t log_length = aeron_logbuffer_compute_log_length(term_length, page_size);
    if (aeron_map_new_os_ipc(&mapped_raw_log->mapped_file, os_ipc, log_length, !use_sparse_files) >= 0)
    {
        for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
        {
            mapped_raw_log->term_buffers[i].addr = (uint8_t *)mapped_raw_log->mapped_file.addr + (i * term_length);
            mapped_raw_log->term_buffers[i].length = term_length;
        }

        mapped_raw_log->log_meta_data.addr =
            (uint8_t *)mapped_raw_log->mapped_file.addr + (log_length - AERON_LOGBUFFER_META_DATA_LENGTH);
        mapped_raw_log->log_meta_data.length = AERON_LOGBUFFER_META_DATA_LENGTH;
        mapped_raw_log->term_length = term_length;

        result = 0;
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }

    return result;
}

int aeron_map_existing_log(
    aeron_mapped_raw_log_t *mapped_raw_log,
    aeron_image_os_ipc_t *os_ipc,
    bool pre_touch)
{
    int result = -1;

    if (aeron_map_existing_os_ipc(&mapped_raw_log->mapped_file, os_ipc, false) >= 0)
    {
        mapped_raw_log->log_meta_data.addr =
            (uint8_t *)mapped_raw_log->mapped_file.addr +
            (mapped_raw_log->mapped_file.length - AERON_LOGBUFFER_META_DATA_LENGTH);
        mapped_raw_log->log_meta_data.length = AERON_LOGBUFFER_META_DATA_LENGTH;

        aeron_logbuffer_metadata_t *log_meta_data = (aeron_logbuffer_metadata_t *)mapped_raw_log->log_meta_data.addr;
        size_t term_length = (size_t)log_meta_data->term_length;
        size_t page_size = (size_t)log_meta_data->page_size;

        if (aeron_logbuffer_check_term_length(term_length) < 0 ||
            aeron_logbuffer_check_page_size(page_size) < 0)
        {
            aeron_unmap(&mapped_raw_log->mapped_file);
            return -1;
        }

        mapped_raw_log->term_length = term_length;

        for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
        {
            mapped_raw_log->term_buffers[i].addr = (uint8_t *)mapped_raw_log->mapped_file.addr + (i * term_length);
            mapped_raw_log->term_buffers[i].length = term_length;
        }

        if (pre_touch)
        {
            volatile int32_t value = 0;

            for (size_t i = 0; i < AERON_LOGBUFFER_PARTITION_COUNT; i++)
            {
                uint8_t *base_addr = mapped_raw_log->term_buffers[i].addr;

                for (size_t offset = 0; offset < term_length; offset += page_size)
                {
                    aeron_cmpxchg32((volatile int32_t *)(base_addr + offset), value, value);
                }
            }
        }

        result = 0;
    }
    else
    {
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }

    return result;
}

int aeron_map_raw_log_close(aeron_mapped_raw_log_t *mapped_raw_log, aeron_image_os_ipc_t *os_ipc)
{
    int result = 0;

    if (mapped_raw_log->mapped_file.addr != NULL)
    {
        if ((result = aeron_unmap(&mapped_raw_log->mapped_file)) < 0)
        {
            result = -1;
        }

        if (NULL != os_ipc && aeron_close_os_ipc(os_ipc) < 0)
        {
            aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
            result = -1;
        }

        mapped_raw_log->mapped_file.addr = NULL;
    }

    return result;
}

#endif