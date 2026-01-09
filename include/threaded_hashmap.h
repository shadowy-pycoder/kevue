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
/**
 * @file threaded_hashmap.h
 * @brief Threaded hash map API.
 */
#pragma once

#include <hashmap.h>

/**
 * Creates a new threaded hashmap instance.
 *
 * Memory is allocated using the provided allocator.
 *
 * @param ma  Allocator used for threaded hashmap memory.
 *
 * @return Pointer to a newly created threaded hashmap, or NULL on failure.
 */
HashMap *kevue_hm_threaded_create(KevueAllocator *ma);
