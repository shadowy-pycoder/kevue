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
 * @file kevue_string.c
 * @brief Custom string implementation.
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <allocator.h>
#include <common.h>
#include <kevue_string.h>

String kevue_string_create(const char *s)
{
    KevueAllocator *ma = kevue_allocator();
    String          str = { 0 };
    str.len = kevue__cstring_len(s);
    if (str.len == 0) return (String) { 0 };
    str.data = (u8 *)ma->malloc(sizeof(*str.data) * str.len, ma->ctx);
    if (str.data == NULL) return (String) { 0 };
    memcpy(str.data, s, str.len);
    return str;
}

String kevue_string_createf(const char *fmt, ...)
{
    KevueAllocator *ma = kevue_allocator();
    String          str = { 0 };
    va_list         ap;
    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len <= 0) return (String) { 0 };
    str.data = (u8 *)ma->malloc(sizeof(*str.data) * (size_t)(len + 1), ma->ctx);
    if (str.data == NULL) return (String) { 0 };
    va_start(ap, fmt);
    int n = vsnprintf((char *)str.data, (size_t)(len + 1), fmt, ap);
    va_end(ap);
    if (n < 0) {
        kevue_string_destroy(&str);
        return (String) { 0 };
    }
    str.len = (u64)len;
    return str;
}

void kevue_string_destroy(String *str)
{
    KevueAllocator *ma = kevue_allocator();
    ma->free(str->data, ma->ctx);
    str->data = NULL;
    str->len = 0;
}

bool kevue_string_is_empty(String str)
{
    return str.data == NULL || str.len == 0;
}

String kevue_string_from_string_view(StringView sv)
{
    KevueAllocator *ma = kevue_allocator();
    if (sv.len == 0) return (String) { 0 };
    String str = (String) { 0 };
    str.len = sv.len;
    str.data = (u8 *)ma->malloc(sizeof(*str.data) * str.len, ma->ctx);
    if (str.data == NULL) {
        return (String) { 0 };
    }
    memcpy(str.data, sv.data, str.len);
    return str;
}

String kevue_string_copy(String str)
{
    KevueAllocator *ma = kevue_allocator();
    if (kevue_string_is_empty(str)) return (String) { 0 };
    String out = (String) { 0 };
    out.len = str.len;
    out.data = (u8 *)ma->malloc(sizeof(*str.data) * str.len, ma->ctx);
    if (out.data == NULL) {
        return (String) { 0 };
    }
    memcpy(out.data, str.data, out.len);
    return out;
}

String kevue_string_to_lower(String str)
{
    if (kevue_string_is_empty(str)) return (String) { 0 };
    String out = kevue_string_copy(str);
    for (u64 i = 0; i < out.len; i++) {
        if (out.data[i] >= 'A' && out.data[i] <= 'Z') {
            out.data[i] |= 1 << 5;
        }
    }
    return out;
}
String kevue_string_to_upper(String str)
{
    if (kevue_string_is_empty(str)) return (String) { 0 };
    String out = kevue_string_copy(str);
    for (u64 i = 0; i < out.len; i++) {
        if (out.data[i] >= 'a' && out.data[i] <= 'z') {
            out.data[i] &= ~(1 << 5);
        }
    }
    return out;
}

String kevue_string_to_title(String str)
{
    if (kevue_string_is_empty(str)) return (String) { 0 };
    String out = kevue_string_copy(str);
    u8    *left = out.data;
    u8    *right = out.data + out.len;
    bool   title_applied = false;
    while (right - left > 0) {
        if (isspace((u8)*left)) {
            while (left < right && isspace((u8)*left)) left++;
            title_applied = false;
            continue;
        }
        if (!title_applied) {
            if (*left >= 'a' && *left <= 'z') {
                *left &= ~(1 << 5);
            }
            title_applied = true;
        } else if (*left >= 'A' && *left <= 'Z') {
            *left |= 1 << 5;
        }
        left++;
    }
    return out;
}

u64 kevue__cstring_len(const char *s)
{
    const u8 *p = (const u8 *)s;
    while (*p++);
    return (u64)(p - (const u8 *)s - 1);
}

StringView kevue_string_view_from_string(String str)
{
    return (StringView) { .data = str.data, .len = str.len };
}

StringView kevue_string_view_from_cstring(const char *s)
{
    return (StringView) { .data = (u8 *)s, .len = kevue__cstring_len(s) };
}

StringView kevue_string_view_from_buffer(Buffer buf)
{
    return (StringView) { .data = buf.ptr, .len = buf.size };
}

bool kevue_string_view_compare(StringView sv1, StringView sv2)
{
    if (sv1.len != sv2.len) return false;
    if (sv1.len == 0) return true;
    return memcmp(sv1.data, sv2.data, sv1.len) == 0;
}

bool kevue_string_view_compare_icase(StringView sv1, StringView sv2)
{
    if (sv1.len != sv2.len) return false;
    for (u64 i = 0; i < sv1.len; i++) {
        u8 c1 = sv1.data[i];
        u8 c2 = sv2.data[i];
        if ((c1 >= 'A' && c1 <= 'Z') || (c1 >= 'a' && c1 <= 'z')) {
            c1 |= (1 << 5);
            c2 |= (1 << 5);
        }
        if (c1 != c2) return false;
    }
    return true;
}

bool kevue_string_view_has_suffix(StringView sv, StringView suffix)
{
    if (suffix.len == 0) return true; // technically this is not needed see https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf 6.5.6p8
    if (sv.len < suffix.len) return false;
    return memcmp(&sv.data[sv.len - suffix.len], suffix.data, suffix.len) == 0;
}

bool kevue_string_view_has_prefix(StringView sv, StringView prefix)
{
    if (prefix.len == 0) return true;
    if (sv.len < prefix.len) return false;
    return memcmp(sv.data, prefix.data, prefix.len) == 0;
}

StringView kevue_string_view_trim_suffix(StringView sv, StringView suffix)
{
    if (kevue_string_view_has_suffix(sv, suffix)) {
        return (StringView) { .data = sv.data, .len = sv.len - suffix.len };
    }
    return sv;
}

StringView kevue_string_view_trim_prefix(StringView sv, StringView prefix)
{
    if (kevue_string_view_has_prefix(sv, prefix)) {
        return (StringView) { .data = sv.data + prefix.len, .len = sv.len - prefix.len };
    }
    return sv;
}

i64 kevue_string_view_index(StringView sv, StringView substr)
{
    if (substr.len == 0) return 0;
    if (substr.len > sv.len) return -1;
    if (sv.data == NULL || substr.data == NULL) return -1;
    u8 *cur = sv.data;
    u8 *sv_end = sv.data + sv.len;
    while (true) {
        cur = (u8 *)memchr(cur, substr.data[0], sv_end - cur);
        if (cur == NULL || (u64)(sv_end - cur) < substr.len) return -1;
        if ((memcmp(cur, substr.data, substr.len)) == 0) {
            return (i64)(cur - sv.data);
        }
        cur++;
    }
    return -1;
}

i64 kevue_string_view_last_index(StringView sv, StringView substr)
{
    if (substr.len == 0) return (i64)sv.len;
    i64 last_index = -1;
    if (substr.len > sv.len) return last_index;
    if (sv.data == NULL || substr.data == NULL) return last_index;
    u8 *cur = sv.data;
    u8 *sv_end = sv.data + sv.len;
    while (true) {
        cur = (u8 *)memchr(cur, substr.data[0], sv_end - cur);
        if (cur == NULL || (u64)(sv_end - cur) < substr.len) return last_index;
        if ((memcmp(cur, substr.data, substr.len)) == 0) {
            last_index = (i64)(cur - sv.data);
        }
        cur++;
    }
    return last_index;
}

bool kevue_string_view_contains(StringView sv, StringView substr)
{
    return kevue_string_view_index(sv, substr) >= 0;
}

StringView kevue_string_view_trim_space(StringView sv)
{
    if (sv.data == NULL || sv.len == 0) return sv;
    u8 *left = sv.data;
    u8 *right = sv.data + sv.len;
    while (left < right && isspace((u8)left[0])) left++;
    while (right > left && isspace((u8)right[-1])) right--;
    return (StringView) { .data = left, .len = (u64)(right - left) };
}

i64 kevue_string_view_byte_index(StringView sv, u8 b)
{
    if (sv.data == NULL) return -1;
    u8 *cur = (u8 *)memchr(sv.data, b, sv.len);
    if (cur == NULL) return -1;
    return (i64)(cur - sv.data);
}

bool kevue_string_view_contains_byte(StringView sv, u8 b)
{
    return kevue_string_view_byte_index(sv, b) >= 0;
}

StringView kevue_string_view_trim_left(StringView sv, StringView cutset)
{
    if (sv.data == NULL || cutset.data == NULL) return (StringView) { 0 };
    u8 *left = sv.data;
    while (left < sv.data + sv.len && kevue_string_view_contains_byte(cutset, *left)) left++;
    return (StringView) { .data = left, .len = sv.len - (u64)(left - sv.data) };
}

StringView kevue_string_view_trim_right(StringView sv, StringView cutset)
{
    if (sv.data == NULL || cutset.data == NULL) return (StringView) { 0 };
    u8 *right = sv.data + sv.len;
    while (right > sv.data && kevue_string_view_contains_byte(cutset, right[-1])) right--;
    return (StringView) { .data = sv.data, .len = (u64)(right - sv.data) };
}

StringView kevue_string_view_trim(StringView sv, StringView cutset)
{
    return kevue_string_view_trim_right(kevue_string_view_trim_left(sv, cutset), cutset);
}
