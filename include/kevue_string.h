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

#include <common.h>

typedef struct String {
    u8 *data;
    u64 len;
} String;

typedef struct StringView {
    u8 *data;
    u64 len;
} StringView;

/**
 * @brief Creates a new string by copying a NUL-terminated C string.
 *
 * Memory is allocated using kevue allocator.
 *
 * @param s   NUL-terminated source string.
 *
 * @return Newly created string owning a copy of the data, or an empty
 *         string on failure.
 */
String kevue_string_create(const char *s);

/**
 * @brief Creates a new string from a printf-style format.
 *
 * The formatted result is written into memory allocated using the provided
 * allocator. Format specifiers and argument rules are the same as for
 * printf. The result must be destroyed with kevue_string_destroy using the
 * same allocator.
 *
 * @param fmt  printf-style format string.
 * @param ...  Arguments matching the format specifiers.
 *
 * @return Newly created formatted string, or an empty string on failure
 */
String kevue_string_createf(const char *fmt, ...) KEVUE_PRINTF_FORMAT(1, 2);

/**
 * @brief Destroys a string and releases its memory.
 *
 * Memory is released using  kevue allocator. The string must have
 * been created with the same allocator. After the call the string is reset
 * and must not be used.
 *
 * @param str  Pointer to the string to destroy.
 */
void kevue_string_destroy(String *str);

/**
 * @brief Creates a new string by copying the contents of a string view.
 *
 * Memory is allocated using kevue allocator. The view does not need
 * to be NUL-terminated, only its length is used.
 *
 * @param sv  Source string view.
 *
 * @return Newly created string owning a copy of the viewed data, or an empty
 *         string on failure.
 */
String kevue_string_from_string_view(StringView sv);

/**
 * @brief Creates a deep copy of a string.
 *
 * Memory is allocated using kevue allocator. The copy is independent
 * of the original and must be destroyed separately.
 *
 * @param str  String to copy.
 *
 * @return Newly created copy of the string, or an empty string on failure.
 */
String kevue_string_copy(String str);

/**
 * @brief Creates a lower case copy of a string.
 *
 * Only ASCII letters A-Z are converted, all other bytes are copied unchanged.
 * The original string is not modified. Memory is allocated using kevue allocator.
 *
 * @param str  Source string.
 *
 * @return Newly created lower case string, or an empty string on failure.
 */
String kevue_string_to_lower(String str);

/**
 * @brief Creates an upper case copy of a string.
 *
 * Only ASCII letters a-z are converted, all other bytes are copied unchanged.
 * The original string is not modified. Memory is allocated using kevue allocator.
 *
 * @param str  Source string.
 *
 * @return Newly created upper case string, or an empty string on failure.
 */
String kevue_string_to_upper(String str);

/**
 * @brief Creates a title case copy of a string.
 *
 * A letter is upper-cased if it is the first byte of the string or follows
 * an ASCII whitespace byte. All other ASCII letters are lower-cased and
 * non-letters are copied unchanged. The original string is not modified.
 * Memory is allocated using kevue allocator.
 *
 * @param str  Source string.
 *
 * @return Newly created title case string, or an empty string on failure.
 */
String kevue_string_to_title(String str);

u64 kevue__cstring_len(const char *s);

#define String(s)         kevue_string_create((s))
#define Stringf(fmt, ...) kevue_string_createf((fmt), ##__VA_ARGS__)

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

/**
 * @brief Creates a string view over the data of a string.
 *
 * No memory is allocated and no data is copied. The view is valid only
 * as long as the source string is alive and unmodified.
 *
 * @param str  Source string.
 *
 * @return View referencing the string's data and length.
 */
StringView kevue_string_view_from_string(String str);

/**
 * @brief Creates a string view over a NUL-terminated C string.
 *
 * No memory is allocated and no data is copied. The length is computed
 * with strlen, the terminating NUL is not included. The view is valid only
 * as long as the source buffer is alive and unmodified.
 *
 * @param s  NUL-terminated source string.
 *
 * @return View referencing the C string's data and length.
 */
StringView kevue_string_view_from_cstring(const char *s);

/**
 * @brief Compares two string views for exact equality.
 *
 * The comparison is case sensitive and byte-wise. Views are equal if they
 * have the same length and the same bytes.
 *
 * @param sv1  First view.
 * @param sv2  Second view.
 *
 * @return true if the views are equal, false otherwise.
 */
bool kevue_string_view_compare(StringView sv1, StringView sv2);

/**
 * @brief Compares two string views for equality ignoring ASCII case.
 *
 * Only ASCII letters are case folded, all other bytes must match exactly.
 *
 * @param sv1  First view.
 * @param sv2  Second view.
 *
 * @return true if the views are equal ignoring ASCII case, false otherwise.
 */
bool kevue_string_view_compare_icase(StringView sv1, StringView sv2);

/**
 * @brief Checks whether a view ends with the given suffix.
 *
 * The comparison is case sensitive. An empty suffix always matches.
 *
 * @param sv      View to check.
 * @param suffix  Suffix to look for.
 *
 * @return true if sv ends with suffix, false otherwise.
 */
bool kevue_string_view_has_suffix(StringView sv, StringView suffix);

/**
 * @brief Checks whether a view starts with the given prefix.
 *
 * The comparison is case sensitive. An empty prefix always matches.
 *
 * @param sv      View to check.
 * @param prefix  Prefix to look for.
 *
 * @return true if sv starts with prefix, false otherwise.
 */
bool kevue_string_view_has_prefix(StringView sv, StringView prefix);

/**
 * @brief Removes a single trailing suffix from a view.
 *
 * If sv does not end with suffix, it is returned unchanged. At most one
 * occurrence is removed. No data is copied.
 *
 * @param sv      Source view.
 * @param suffix  Suffix to remove.
 *
 * @return View without the suffix, or sv if the suffix did not match.
 */
StringView kevue_string_view_trim_suffix(StringView sv, StringView suffix);

/**
 * @brief Removes a single leading prefix from a view.
 *
 * If sv does not start with prefix, it is returned unchanged. At most one
 * occurrence is removed. No data is copied.
 *
 * @param sv      Source view.
 * @param prefix  Prefix to remove.
 *
 * @return View without the prefix, or sv if the prefix did not match.
 */
StringView kevue_string_view_trim_prefix(StringView sv, StringView prefix);

/**
 * @brief Finds the first occurrence of a substring in a view.
 *
 * An empty substring matches at index 0.
 *
 * @param sv      View to search in.
 * @param substr  Substring to look for.
 *
 * @return Byte offset of the first match, or -1 if not found.
 */
i64 kevue_string_view_index(StringView sv, StringView substr);

/**
 * @brief Finds the last occurrence of a substring in a view.
 *
 * Overlapping matches are considered. An empty substring matches at the
 * length of sv.
 *
 * @param sv      View to search in.
 * @param substr  Substring to look for.
 *
 * @return Byte offset of the last match, or -1 if not found.
 */
i64 kevue_string_view_last_index(StringView sv, StringView substr);

/**
 * @brief Checks whether a view contains a substring.
 *
 * Equivalent to kevue_string_view_index(sv, substr) >= 0.
 *
 * @param sv      View to search in.
 * @param substr  Substring to look for.
 *
 * @return true if substr occurs in sv, false otherwise.
 */
bool kevue_string_view_contains(StringView sv, StringView substr);

/**
 * @brief Finds the first occurrence of a byte in a view.
 *
 * @param sv  View to search in.
 * @param b   Byte to look for.
 *
 * @return Byte offset of the first match, or -1 if not found.
 */
i64 kevue_string_view_byte_index(StringView sv, u8 b);

/**
 * @brief Checks whether a view contains a byte.
 *
 * @param sv  View to search in.
 * @param b   Byte to look for.
 *
 * @return true if b occurs in sv, false otherwise.
 */
bool kevue_string_view_contains_byte(StringView sv, u8 b);

/**
 * @brief Removes leading and trailing ASCII whitespace from a view.
 *
 * Whitespace is space, \\t, \\n, \\v, \\f and \\r. Other bytes, including
 * control characters and bytes >= 0x80, are kept. No data is copied.
 *
 * @param sv  Source view.
 *
 * @return View without leading and trailing whitespace.
 */
StringView kevue_string_view_trim_space(StringView sv);

/**
 * @brief Removes leading bytes that are present in a cutset.
 *
 * The cutset is treated as a set of bytes, order and duplicates do not
 * matter. Matching is case sensitive. An empty cutset leaves the view
 * unchanged. No data is copied.
 *
 * @param sv      Source view.
 * @param cutset  Bytes to remove from the start.
 *
 * @return View without the leading cutset bytes.
 */
StringView kevue_string_view_trim_left(StringView sv, StringView cutset);

/**
 * @brief Removes trailing bytes that are present in a cutset.
 *
 * The cutset is treated as a set of bytes, order and duplicates do not
 * matter. Matching is case sensitive. An empty cutset leaves the view
 * unchanged. No data is copied.
 *
 * @param sv      Source view.
 * @param cutset  Bytes to remove from the end.
 *
 * @return View without the trailing cutset bytes.
 */
StringView kevue_string_view_trim_right(StringView sv, StringView cutset);

/**
 * @brief Removes leading and trailing bytes that are present in a cutset.
 *
 * Equivalent to trim_left followed by trim_right with the same cutset.
 * No data is copied.
 *
 * @param sv      Source view.
 * @param cutset  Bytes to remove from both ends.
 *
 * @return View without the leading and trailing cutset bytes.
 */
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
