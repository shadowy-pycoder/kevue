/*
 * Copyright 2025-2026 shadowy-pycoder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#if (defined(USE_TCMALLOC) + defined(USE_JEMALLOC) + defined(USE_MIMALLOC) + defined(USE_ARENA)) > 1
#error "You can define only one memory allocator at a time"
#endif
#if defined(USE_TCMALLOC)
#include "../src/tcmalloc_allocator.c"
#elif defined(USE_JEMALLOC)
#include "../src/jemalloc_allocator.c"
#elif defined(USE_MIMALLOC)
#include "../src/mimalloc_allocator.c"
#elif defined(USE_ARENA)
#include "../src/arena_allocator.c"
#else
#include "../src/allocator.c"
#endif
