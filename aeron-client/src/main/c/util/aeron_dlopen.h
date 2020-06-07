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

#ifndef AERON_DLOPEN_H
#define AERON_DLOPEN_H

#include <util/aeron_platform.h>

#if defined(AERON_COMPILER_GCC)

#include <dlfcn.h>
#include <stddef.h>

#define aeron_dlsym dlsym
#define aeron_dlopen(x) dlopen(x, RTLD_LAZY)
#define aeron_dlerror dlerror

const char *aeron_dlinfo(const void *addr, char *buffer, size_t max_buffer_length);

#elif defined(AERON_COMPILER_MSVC)

#define RTLD_DEFAULT ((void*)-123)
#define RTLD_NEXT ((void*)-124)

void* aeron_dlsym(void* module, const char* name);
void* aeron_dlopen(const char* filename);
char* aeron_dlerror();
const char *aeron_dlinfo(const void* addr, char* buffer, size_t max_buffer_length);

#else
#error Unsupported platform!
#endif

#endif //AERON_DLOPEN_H
