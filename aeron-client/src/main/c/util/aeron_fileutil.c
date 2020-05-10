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
#include <inttypes.h>

#include "aeron_platform.h"
#include "aeron_error.h"
#include "aeron_fileutil.h"

/* pid/$PID/type/$TYPE/fd/$FD */
#define AERON_LOG_BUFFER_FILENAME_PREFIX "aeron_log_buffer://"
#define AERON_LOG_BUFFER_FILENAME_FORMATTER "pid=%" PRIi64 ",type=%d,id=%" PRIi64 ",length=%" PRIi64

int aeron_parse_log_buffer_filename(const char* filename, int64_t *pid, int *type, int64_t *id, int64_t *length, int64_t *fd)
{
    return sscanf(filename + sizeof(AERON_LOG_BUFFER_FILENAME_PREFIX) - 1, AERON_LOG_BUFFER_FILENAME_FORMATTER ",fd=%"PRId64, pid, type, id, length, fd);
}

#if defined(AERON_COMPILER_MSVC)
#define _CRT_RAND_S
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <io.h>
#include <direct.h>

int aeron_mmap(aeron_mapped_file_t *mapping, const char *filename, uint64_t size, uint64_t offset, bool read_only, bool creating_new)
{
    HANDLE hmap = INVALID_HANDLE_VALUE;
    int64_t pid;
    int buffer_type;
    int64_t buffer_id;
    int64_t length;
    int64_t tmp_fd;
    int parse_cout = aeron_parse_log_buffer_filename(filename, &pid, &buffer_type, &buffer_id, &length, &tmp_fd);
    if (parse_cout > 0)
    {
        char filename_to_open[AERON_MAX_PATH];
        if (parse_cout < 5)
        {
            aeron_set_err_from_last_err_code("aeron_log_buffer %s doesn't have enough parameter attribute", filename);
            return -1;
        }
        snprintf(filename_to_open, sizeof(filename_to_open) - 1, AERON_LOG_BUFFER_FILENAME_PREFIX AERON_LOG_BUFFER_FILENAME_FORMATTER, pid, buffer_type, buffer_id, length);
        hmap = OpenFileMappingA(SECTION_MAP_WRITE | SECTION_MAP_READ, FALSE, filename_to_open);
        size = length;
    }
    else
    {
        const DWORD dwSharedMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        HANDLE fileHandle;
        if (creating_new)
        {
            fileHandle = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, dwSharedMode, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (fileHandle == NULL || fileHandle == INVALID_HANDLE_VALUE)
            {
                aeron_set_err_from_last_err_code("creating %s failed", filename);
                return -1;
            }

            LARGE_INTEGER loffset;
            loffset.QuadPart = size;
            if (SetFilePointerEx(fileHandle, loffset, 0, FILE_BEGIN) == 0)
            {
                aeron_set_err_from_last_err_code("seek for %s failed", filename);
                CloseHandle(fileHandle);
                aeron_unlink(filename);
                return -1;
            }

            if (SetEndOfFile(fileHandle) == 0)
            {
                aeron_set_err_from_last_err_code("resize for %s failed", filename);
                CloseHandle(fileHandle);
                aeron_unlink(filename);
                return -1;
            }
        }
        else
        {
            DWORD dwDesiredAccess = read_only ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
            fileHandle = CreateFileA(filename, dwDesiredAccess, dwSharedMode, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (fileHandle == NULL || fileHandle == INVALID_HANDLE_VALUE)
            {
                aeron_set_err_from_last_err_code("open existing faile %s failed", filename);
                return -1;
            }
            if (size == 0)
            {
                LARGE_INTEGER lsize;
                if (GetFileSizeEx(fileHandle, &lsize) == 0)
                {
                    aeron_set_err_from_last_err_code("retrieve file size for %s failed", filename);
                    CloseHandle(fileHandle);
                    return -1;
                }
                size = lsize.QuadPart;
            }
        }
        DWORD flProtect = read_only ? PAGE_READONLY : PAGE_READWRITE;
        hmap = CreateFileMappingA(fileHandle, NULL, flProtect, (DWORD)(size >> 32), (DWORD)(size & UINT32_MAX), NULL);
        CloseHandle(fileHandle);
        if (!hmap)
        {
            aeron_set_err_from_last_err_code("CreateFileMapping for %s failed", filename);
            return -1;
        }
    }
    if (hmap == NULL || hmap == INVALID_HANDLE_VALUE)
    {
        aeron_set_err_from_last_err_code("prepare the file handle for %s failed", filename);
        return -1;
    }

    if (read_only)
    {
        mapping->addr = MapViewOfFileEx(hmap, FILE_MAP_READ, (DWORD)(offset >> 32), (DWORD)(offset & UINT32_MAX), (SIZE_T)size, NULL);
    }
    else
    {
        mapping->addr = MapViewOfFileEx(hmap, FILE_MAP_WRITE, (DWORD)(offset >> 32), (DWORD)(offset & UINT32_MAX), (SIZE_T)size, NULL);
    }
    mapping->length = size;

    if (!CloseHandle(hmap))
    {
        fprintf(stderr, "unable to close file mapping handle when aeron_mmap\n");
    }

    return mapping->addr == NULL ? -1 : 0;
}

int aeron_unmap(aeron_mapped_file_t *mapped_file)
{
    if (NULL != mapped_file->addr)
    {
        return UnmapViewOfFile(mapped_file->addr) ? 0 : -1;
    }

    return 0;
}

int64_t aeron_file_length(const char *path)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;

    if (GetFileAttributesEx(path, GetFileExInfoStandard, &fad) == 0)
    {
        return -1;
    }

    LARGE_INTEGER file_size;
    file_size.LowPart = fad.nFileSizeLow;
    file_size.HighPart = fad.nFileSizeHigh;

    return file_size.QuadPart;
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

int aeron_is_directory(const char *path)
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

#ifdef __linux__
#include <sys/syscall.h>
#ifdef __NR_memfd_create
#include <linux/memfd.h>
#endif
/* #undef  __NR_memfd_create */
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 2U
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif

#endif /* __linux__ */

#if !defined(__NR_memfd_create) && !defined(__FreeBSD__)

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

size_t base64_encode(
    unsigned char *encoded_data,
    const unsigned char *data,
    size_t input_length)
{

    size_t output_length = 4 * ((input_length + 2) / 3);

    if (encoded_data == NULL)
        return 0;

    for (size_t i = 0, j = 0; i < input_length;)
    {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';

    return output_length;
}

int aeron_shm_filename_create(char* filename, size_t filename_max_length, int64_t pid, int buffer_type, int64_t buffer_id)
{
    uint64_t filename_bytes[2];
    uint32_t high = (buffer_type << 24) | 26838;
    filename_bytes[0] = ((uint64_t)high << 32) | pid;
    filename_bytes[1] = buffer_id;
    int tmp_dir_length = snprintf(filename, filename_max_length, "%s", "/");
    size_t base64_encoded_length = base64_encode((unsigned char *)(filename + tmp_dir_length), (const unsigned char *)filename_bytes, sizeof(filename_bytes));
    filename[tmp_dir_length + base64_encoded_length] = 0;
    return tmp_dir_length + base64_encoded_length;
}
#endif

int aeron_mmap(aeron_mapped_file_t *mapping, const char *filename, uint64_t size, uint64_t offset, bool read_only, bool creating_new)
{
    int64_t pid;
    int buffer_type;
    int64_t buffer_id;
    int64_t length;
    int64_t tmp_fd;
    int parse_cout = aeron_parse_log_buffer_filename(filename, &pid, &buffer_type, &buffer_id, &length, &tmp_fd);
    int fd = -1;
    if (parse_cout > 0)
    {
        char filename_to_open[AERON_MAX_PATH];
        if (parse_cout < 5)
        {
            aeron_set_err_from_last_err_code("aeron_log_buffer %s doesn't have enough parameter attribute", filename);
            return -1;
        }
        size = length;
#if defined(__NR_memfd_create)
        sprintf(filename_to_open, "/proc/%ld/fd/%d", (long)pid, (int)tmp_fd);
        fd = open(filename_to_open, O_RDWR);
#elif defined(__FreeBSD__)
#error TODO:
#else
        aeron_shm_filename_create(filename_to_open, sizeof(filename_to_open) - 1, pid, buffer_type, buffer_id);
        fd = shm_open(filename_to_open, O_RDWR, 0);
#endif
    }
    else
    {
        if (creating_new)
        {
            fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            if (fd >= 0)
            {
                if (ftruncate(fd, (off_t)size) < 0)
                {
                    aeron_set_err_from_last_err_code("ftruncate for %s failed", filename);
                    close(fd);
                    aeron_unlink(filename);
                    return -1;
                }
            }
        }
        else
        {
            fd = open(filename, O_RDWR);
            if (fd >=0 && size == 0)
            {
                struct stat s;
                if (fstat(fd, &s) == -1) {
                    aeron_set_err_from_last_err_code("retrieve file size for %s failed", filename);
                    close(fd);
                    return(-1);
                }
                size = s.st_size;
            }
        }
    }
    if (fd < 0)
    {
        aeron_set_err_from_last_err_code("prepare the file handle for %s failed", filename);
        return -1;
    }

    if (read_only)
    {
        mapping->addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, (off_t)offset);
    }
    else
    {
        mapping->addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)offset);
    }
    mapping->length = size;
    close(fd);

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

int aeron_is_directory(const char *dirname)
{
    struct stat sb;
    return stat(dirname, &sb) == 0 && S_ISDIR(sb.st_mode);
}

int64_t aeron_file_length(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 ? sb.st_size : -1;
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

#endif

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
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
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

int aeron_log_buffer_filename_create_direct(
    char* filename,
    size_t filename_max_length,
    int buffer_type, 
    int64_t buffer_id,
    uint64_t log_length
)
{
    char tmp_filename[AERON_MAX_PATH];
    filename[0] = 0;
    int64_t pid = aeron_get_pid();
    snprintf(tmp_filename, sizeof(tmp_filename) - 1, AERON_LOG_BUFFER_FILENAME_PREFIX AERON_LOG_BUFFER_FILENAME_FORMATTER,
        pid, buffer_type, buffer_id, log_length);
#ifdef _WIN32
    HANDLE hmap = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, (DWORD)(log_length >> 32), (DWORD)(log_length & UINT32_MAX), tmp_filename);
    if (hmap == NULL || hmap == INVALID_HANDLE_VALUE) {
        aeron_set_err_from_last_err_code("aeron_log_buffer_filename_create %s failed", tmp_filename);
        return -1;
    }
    return snprintf(filename, filename_max_length, "%s,fd=%"PRId64, tmp_filename, (int64_t)(intptr_t)hmap);
#else
    int fd = -1;
#if defined(__NR_memfd_create)
    fd = syscall(__NR_memfd_create, tmp_filename, MFD_ALLOW_SEALING);
#elif defined(__FreeBSD__)
    fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
#else
    char unix_tmp_filename[AERON_MAX_PATH];
    aeron_shm_filename_create(unix_tmp_filename, sizeof(unix_tmp_filename), pid, buffer_type, buffer_id);
#if defined(__APPLE__)
    shm_unlink(unix_tmp_filename);
#endif
    fd = shm_open(unix_tmp_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
#endif /* __NR_memfd_create*/
    if (fd >= 0)
    {
        if (ftruncate(fd, (off_t)log_length) < 0)
        {
            aeron_set_err_from_last_err_code("aeron_log_buffer_filename_create ftruncate %s failed", tmp_filename);
            close(fd);
            return -1;
        }
#if defined(__NR_memfd_create) && defined(F_ADD_SEALS)
        if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW) < 0)
        {
            aeron_set_err_from_last_err_code("aeron_log_buffer_filename_create F_SEAL_SHRINK %s failed", tmp_filename);
            close(fd);
            return -1;
        }
#endif
    }
    else
    {
        aeron_set_err_from_last_err_code("creating %s failed", tmp_filename);
        return -1;
    }
    return snprintf(filename, filename_max_length, "%s,fd=%d", tmp_filename, fd);
#endif /* _WIN32 */
}

int aeron_log_buffer_filename_delete(const char* filename)
{
    int result = -1;
    int64_t pid;
    int buffer_type;
    int64_t buffer_id;
    int64_t length;
    int64_t fd;
    int parse_cout = aeron_parse_log_buffer_filename(filename, &pid, &buffer_type, &buffer_id, &length, &fd);
    if (parse_cout > 0)
    {
        if (parse_cout < 5)
        {
            aeron_set_err_from_last_err_code("%s doesn't have fd attribute", filename);
            return -1;
        }
#ifdef _WIN32
        if (CloseHandle((HANDLE)fd))
        {
            result = 0;
        }
#else
#if !defined(__NR_memfd_create) && !defined(__FreeBSD__)
        char unix_tmp_filename[AERON_MAX_PATH];
        aeron_shm_filename_create(unix_tmp_filename, sizeof(unix_tmp_filename), pid, buffer_type, buffer_id);
        if (shm_unlink(unix_tmp_filename) < 0)
        {
            aeron_set_err_from_last_err_code("aeron_log_buffer_filename_create shm_unlink %s failed", unix_tmp_filename);
        }
#endif
        close((int)fd);
        result = 0;
#endif /* _WIN32 */
    }
    else
    {
        result = aeron_unlink(filename);
    }

    if (result != 0)
    {
        aeron_set_err_from_last_err_code("aeron_log_buffer_filename_delete %s failed", filename);
    }
    return result;
}

int64_t aeron_log_buffer_file_length(const char* filename)
{
    int64_t pid;
    int type;
    int64_t id;
    int64_t length;
    int64_t fd;
    int parse_cout = aeron_parse_log_buffer_filename(filename, &pid, &type, &id, &length, &fd);
    if (parse_cout > 0)
    {
        if (parse_cout < 5)
        {
            aeron_set_err_from_last_err_code("%s doesn't have length attribute", filename);
            return -1;
        }
        return length;
    }
    else
    {
        return aeron_file_length(filename);
    }
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

int aeron_map_new_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool fill_with_zeroes)
{
    int result = -1;

    if (aeron_mmap(mapped_file, path, size, offset, false, true) >= 0)
    {
        if (fill_with_zeroes)
        {
            aeron_touch_pages(mapped_file->addr, mapped_file->length, aeron_get_page_size());
        }
        result = 0;
    }
    else
    {
        mapped_file->addr = NULL;
        mapped_file->length = 0;
        aeron_set_err_from_last_err_code("%s:%d", __FILE__, __LINE__);
    }
    return result;
}

int aeron_map_existing_file(aeron_mapped_file_t *mapped_file, const char *path, size_t size, uint64_t offset, bool read_only)
{
    int result = -1;

    if (aeron_mmap(mapped_file, path, size, offset, read_only, false) >= 0)
    {
        result = 0;
    }
    else
    {
        mapped_file->addr = NULL;
        mapped_file->length = 0;
    }
    return result;
}

uint64_t aeron_usable_fs_space_disabled(const char *path)
{
    return UINT64_MAX;
}

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunused-function"
#endif

inline static const char *tmp_dir()
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

inline static bool has_file_separator_at_end(const char *path)
{
#if defined(_MSC_VER)
    const char last = path[strlen(path) - 1];
    return last == '\\' || last == '/';
#else
    return path[strlen(path) - 1] == '/';
#endif
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

inline static const char *username()
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

int aeron_default_path(char *path, size_t path_length)
{
#if defined(__linux__)
    return snprintf(path, path_length, "/dev/shm/aeron-%s", username());
#elif defined(_MSC_VER)
    return snprintf(
        path, path_length, "%s%saeron-%s", tmp_dir(), has_file_separator_at_end(tmp_dir()) ? "" : "\\", username());
#else
    return snprintf(
        path, path_length, "%s%saeron-%s", tmp_dir(), has_file_separator_at_end(tmp_dir()) ? "" : "/", username());
#endif
}
