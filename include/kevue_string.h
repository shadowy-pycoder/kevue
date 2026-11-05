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
 * @file kevue_string.h
 * @brief String API.
 */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include <allocator.h>
#include <common.h>

typedef struct String {
    u8 *data;
    u64 len;
} String;

typedef struct StringView {
    u8 *data;
    u64 len;
} StringView;

String kevue_string_create(const char *s, KevueAllocator *ma);
void kevue_string_destroy(String *str, KevueAllocator *ma);
String kevue_string_from_string_view(StringView sv, KevueAllocator *ma);
String kevue_string_copy(String str, KevueAllocator *ma);
String kevue_string_to_lower(String str, KevueAllocator *ma);
String kevue_string_to_upper(String str, KevueAllocator *ma);
String kevue_string_to_title(String str, KevueAllocator *ma);

u64 kevue__cstring_len(const char *s);

#define StringView(s) \
    (StringView) { .data = (s).data, .len = (s).len }

#define StringViewFromCString(s) \
    (StringView) { .data = (u8 *)(s), .len = kevue__cstring_len((s)) }

#define StringViewFromLiteral(s) \
    (StringView) { .data = (u8 *)(s), .len = sizeof((s)) - 1 }

#ifndef STR_FMT
#define STR_FMT "%.*s"
#endif // STR_FMT
#ifndef STR_ARG
#define STR_ARG(sv) (int)(sv).len, (sv).data
#endif // STR_ARG

StringView kevue_string_view_from_string(String str);
StringView kevue_string_view_from_cstring(const char *s);
bool kevue_string_view_compare(StringView sv1, StringView sv2);
bool kevue_string_view_compare_icase(StringView sv1, StringView sv2);
bool kevue_string_view_has_suffix(StringView sv, StringView suffix);
bool kevue_string_view_has_prefix(StringView sv, StringView prefix);
StringView kevue_string_view_trim_suffix(StringView sv, StringView suffix);
StringView kevue_string_view_trim_prefix(StringView sv, StringView prefix);
i64 kevue_string_view_index(StringView sv, StringView substr);
i64 kevue_string_view_last_index(StringView sv, StringView substr);
bool kevue_string_view_contains(StringView sv, StringView substr);
i64 kevue_string_view_byte_index(StringView sv, u8 b);
bool kevue_string_view_contains_byte(StringView sv, u8 b);
StringView kevue_string_view_trim_space(StringView sv);
StringView kevue_string_view_trim_left(StringView sv, StringView cutset);
StringView kevue_string_view_trim_right(StringView sv, StringView cutset);
StringView kevue_string_view_trim(StringView sv, StringView cutset);

// Index of substring
// HasSuffix
// HasPrefix
// Contains subsr
// Join by sep
// Split
// Trim dor cutset
// TrimPrefix TrimSuffix for literal match
// utf-8 support
