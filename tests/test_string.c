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

// clang -g3 -Iinclude -Ilib ./src/allocator.c ./tests/test_string.c -o ./bin/kevue-test-string -DDEBUG
#include <assert.h>

#include "../src/buffer.c"
#include "../src/kevue_string.c"
#include "dyna.h"
#include <allocator.h>
#include <common.h>
#include <kevue_string.h>

KevueAllocator *ma = &kevue_default_allocator;
#if defined(USE_TCMALLOC)
ma = &kevue_tcmalloc_allocator;
#elif defined(USE_JEMALLOC)
ma = &kevue_jemalloc_allocator;
#endif

void test_string_create(void)
{
    char  *s = "Hello, World";
    String str = kevue_string_create(s);
    assert(str.len == strlen(s));
    kevue_string_destroy(&str);
    assert(str.data == NULL && str.len == 0);
    printf("%s PASSED\n", __func__);
}

void test_string_create_macro(void)
{
    char  *s = "Hello, World";
    String str = String(s);
    assert(str.len == strlen(s));
    kevue_string_destroy(&str);
    assert(str.data == NULL && str.len == 0);
    printf("%s PASSED\n", __func__);
}

void test_string_createf(void)
{
    String      str = kevue_string_createf("Hello, World %d\n", 5);
    const char *expected = "Hello, World 5\n";
    assert(str.len == strlen(expected));
    assert(memcmp(str.data, expected, str.len) == 0);
    kevue_string_destroy(&str);
    assert(str.data == NULL && str.len == 0);
    printf("%s PASSED\n", __func__);
}

void test_string_createf_macro(void)
{
    String      str = Stringf("Hello, World %d\n", 5);
    const char *expected = "Hello, World 5\n";
    assert(str.len == strlen(expected));
    assert(memcmp(str.data, expected, str.len) == 0);
    kevue_string_destroy(&str);
    assert(str.data == NULL && str.len == 0);
    printf("%s PASSED\n", __func__);
}

void test_string_from_string_view(void)
{
    StringView sv = StringViewFromLiteral("Hello, World");
    String     str = kevue_string_from_string_view(sv);
    assert(str.len == sv.len);
    assert(str.data != sv.data);
    assert(memcmp(str.data, sv.data, str.len) == 0);
    kevue_string_destroy(&str);
    printf("%s PASSED\n", __func__);
}

void test_string_copy(void)
{
    char  *s = "Hello, World";
    String str1 = kevue_string_create(s);
    String str2 = kevue_string_copy(str1);
    assert(str2.len == str1.len);
    assert(str2.data != str1.data);
    assert(memcmp(str2.data, str1.data, str2.len) == 0);
    kevue_string_destroy(&str1);
    kevue_string_destroy(&str2);
    printf("%s PASSED\n", __func__);
}

void test_string_copy_empty(void)
{
    char  *s = "Hello, World";
    String str1 = { 0 };
    String str2 = kevue_string_copy(str1);
    assert(kevue_string_is_empty(str1));
    assert(kevue_string_is_empty(str2));
    printf("%s PASSED\n", __func__);
}

void test_string_to_lower(void)
{
    const char *actual[] = {
        "",
        " ",
        "a",
        "A",
        "hello",
        "HELLO",
        "Hello",
        "hELLO",
        "hello world",
        "HELLO WORLD",
        "hElLo WoRlD",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "@AZ[",
        "`az{",
        "@[`{",
        "0123456789",
        "abc123def",
        "123abc",
        "3rd place",
        "  leading spaces",
        "trailing spaces  ",
        "multiple   spaces   between",
        "tab\tseparated\twords",
        "new\nline\nseparated",
        "hyphen-ated-word",
        "under_score_word",
        "dot.separated.words",
        "don't stop",
        "o'neil's book",
        "rock'n'roll",
        "(parenthesized words)",
        "\"quoted words\"",
        "end.Start",
        "a b c d e",
        "snake_case_name",
        "camelCaseName",
        "PascalCaseName",
        "SCREAMING_SNAKE_CASE",
        "john ronald reuel tolkien",
        "HTTP/1.1 200 OK",
        "content-type: text/html",
        "C:\\Windows\\System32",
        "user@example.com",
        "https://Example.COM/Path?Query=1",
        "int main(void) { return 0; }",
    };

    const char *expected[] = {
        "",
        " ",
        "a",
        "a",
        "hello",
        "hello",
        "hello",
        "hello",
        "hello world",
        "hello world",
        "hello world",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdefghijklmnopqrstuvwxyz",
        "@az[",
        "`az{",
        "@[`{",
        "0123456789",
        "abc123def",
        "123abc",
        "3rd place",
        "  leading spaces",
        "trailing spaces  ",
        "multiple   spaces   between",
        "tab\tseparated\twords",
        "new\nline\nseparated",
        "hyphen-ated-word",
        "under_score_word",
        "dot.separated.words",
        "don't stop",
        "o'neil's book",
        "rock'n'roll",
        "(parenthesized words)",
        "\"quoted words\"",
        "end.start",
        "a b c d e",
        "snake_case_name",
        "camelcasename",
        "pascalcasename",
        "screaming_snake_case",
        "john ronald reuel tolkien",
        "http/1.1 200 ok",
        "content-type: text/html",
        "c:\\windows\\system32",
        "user@example.com",
        "https://example.com/path?query=1",
        "int main(void) { return 0; }",
    };
    for (int i = 0; i < sizeof(actual) / sizeof(actual[0]); i++) {
        String actual_str = kevue_string_create(actual[i]);
        String actual_str_lower = kevue_string_to_lower(actual_str);
        String expected_str = kevue_string_create(expected[i]);
        if (kevue_string_is_empty(expected_str)) {
            assert(kevue_string_is_empty(actual_str));
            assert(kevue_string_is_empty(actual_str_lower));
        } else {
            assert(expected_str.len == actual_str_lower.len);
            assert(expected_str.data != actual_str_lower.data);
            assert(memcmp(expected_str.data, actual_str_lower.data, expected_str.len) == 0);
            kevue_string_destroy(&actual_str);
            kevue_string_destroy(&actual_str_lower);
            kevue_string_destroy(&expected_str);
        }
    }
    printf("%s PASSED\n", __func__);
}

void test_string_to_upper(void)
{
    const char *actual[] = {
        "",
        " ",
        "a",
        "A",
        "hello",
        "HELLO",
        "Hello",
        "hELLO",
        "hello world",
        "HELLO WORLD",
        "hElLo WoRlD",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "@AZ[",
        "`az{",
        "@[`{",
        "0123456789",
        "abc123def",
        "123abc",
        "3rd place",
        "  leading spaces",
        "trailing spaces  ",
        "multiple   spaces   between",
        "tab\tseparated\twords",
        "new\nline\nseparated",
        "hyphen-ated-word",
        "under_score_word",
        "dot.separated.words",
        "don't stop",
        "o'neil's book",
        "rock'n'roll",
        "(parenthesized words)",
        "\"quoted words\"",
        "end.Start",
        "a b c d e",
        "snake_case_name",
        "camelCaseName",
        "PascalCaseName",
        "SCREAMING_SNAKE_CASE",
        "john ronald reuel tolkien",
        "HTTP/1.1 200 OK",
        "content-type: text/html",
        "C:\\Windows\\System32",
        "user@example.com",
        "https://Example.COM/Path?Query=1",
        "int main(void) { return 0; }",
    };
    const char *expected[] = {
        "",
        " ",
        "A",
        "A",
        "HELLO",
        "HELLO",
        "HELLO",
        "HELLO",
        "HELLO WORLD",
        "HELLO WORLD",
        "HELLO WORLD",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "@AZ[",
        "`AZ{",
        "@[`{",
        "0123456789",
        "ABC123DEF",
        "123ABC",
        "3RD PLACE",
        "  LEADING SPACES",
        "TRAILING SPACES  ",
        "MULTIPLE   SPACES   BETWEEN",
        "TAB\tSEPARATED\tWORDS",
        "NEW\nLINE\nSEPARATED",
        "HYPHEN-ATED-WORD",
        "UNDER_SCORE_WORD",
        "DOT.SEPARATED.WORDS",
        "DON'T STOP",
        "O'NEIL'S BOOK",
        "ROCK'N'ROLL",
        "(PARENTHESIZED WORDS)",
        "\"QUOTED WORDS\"",
        "END.START",
        "A B C D E",
        "SNAKE_CASE_NAME",
        "CAMELCASENAME",
        "PASCALCASENAME",
        "SCREAMING_SNAKE_CASE",
        "JOHN RONALD REUEL TOLKIEN",
        "HTTP/1.1 200 OK",
        "CONTENT-TYPE: TEXT/HTML",
        "C:\\WINDOWS\\SYSTEM32",
        "USER@EXAMPLE.COM",
        "HTTPS://EXAMPLE.COM/PATH?QUERY=1",
        "INT MAIN(VOID) { RETURN 0; }",
    };
    for (int i = 0; i < sizeof(actual) / sizeof(actual[0]); i++) {
        String actual_str = kevue_string_create(actual[i]);
        String actual_str_upper = kevue_string_to_upper(actual_str);
        String expected_str = kevue_string_create(expected[i]);
        if (kevue_string_is_empty(expected_str)) {
            assert(kevue_string_is_empty(actual_str));
            assert(kevue_string_is_empty(actual_str_upper));
        } else {
            assert(expected_str.len == actual_str_upper.len);
            assert(expected_str.data != actual_str_upper.data);
            assert(memcmp(expected_str.data, actual_str_upper.data, expected_str.len) == 0);
            kevue_string_destroy(&actual_str);
            kevue_string_destroy(&actual_str_upper);
            kevue_string_destroy(&expected_str);
        }
    }
    printf("%s PASSED\n", __func__);
}

void test_string_to_title(void)
{
    const char *actual[] = {
        "",
        " ",
        " \t\v",
        "a",
        "A",
        "hello",
        "HELLO",
        "Hello",
        "hELLO",
        "hello world",
        "HELLO WORLD",
        "hElLo WoRlD",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "@AZ[",
        "`az{",
        "@[`{",
        "0123456789",
        "abc123def",
        "123abc",
        "3rd place",
        "  leading spaces",
        "trailing spaces  ",
        "multiple   spaces   between",
        "tab\tseparated\twords",
        "new\nline\nseparated",
        "hyphen-ated-word",
        "under_score_word",
        "dot.separated.words",
        "don't stop",
        "o'neil's book",
        "rock'n'roll",
        "(parenthesized words)",
        "\"quoted words\"",
        "end.Start",
        "a b c d e",
        "snake_case_name",
        "camelCaseName",
        "PascalCaseName",
        "SCREAMING_SNAKE_CASE",
        "john ronald reuel tolkien",
        "HTTP/1.1 200 OK",
        "content-type: text/html",
        "C:\\Windows\\System32",
        "user@example.com",
        "https://Example.COM/Path?Query=1",
        "int main(void) { return 0; }",
    };

    const char *expected[] = {
        "",
        " ",
        " \t\v",
        "A",
        "A",
        "Hello",
        "Hello",
        "Hello",
        "Hello",
        "Hello World",
        "Hello World",
        "Hello World",
        "Abcdefghijklmnopqrstuvwxyz",
        "Abcdefghijklmnopqrstuvwxyz",
        "Abcdefghijklmnopqrstuvwxyz",
        "@az[",
        "`az{",
        "@[`{",
        "0123456789",
        "Abc123def",
        "123abc",
        "3rd Place",
        "  Leading Spaces",
        "Trailing Spaces  ",
        "Multiple   Spaces   Between",
        "Tab\tSeparated\tWords",
        "New\nLine\nSeparated",
        "Hyphen-ated-word",
        "Under_score_word",
        "Dot.separated.words",
        "Don't Stop",
        "O'neil's Book",
        "Rock'n'roll",
        "(parenthesized Words)",
        "\"quoted Words\"",
        "End.start",
        "A B C D E",
        "Snake_case_name",
        "Camelcasename",
        "Pascalcasename",
        "Screaming_snake_case",
        "John Ronald Reuel Tolkien",
        "Http/1.1 200 Ok",
        "Content-type: Text/html",
        "C:\\windows\\system32",
        "User@example.com",
        "Https://example.com/path?query=1",
        "Int Main(void) { Return 0; }",
    };

    for (int i = 0; i < sizeof(actual) / sizeof(actual[0]); i++) {
        String actual_str = kevue_string_create(actual[i]);
        String actual_str_title = kevue_string_to_title(actual_str);
        String expected_str = kevue_string_create(expected[i]);
        if (kevue_string_is_empty(expected_str)) {
            assert(kevue_string_is_empty(actual_str));
            assert(kevue_string_is_empty(actual_str_title));
        } else {
            assert(expected_str.len == actual_str_title.len);
            assert(expected_str.data != actual_str_title.data);
            assert(memcmp(expected_str.data, actual_str_title.data, expected_str.len) == 0);
            kevue_string_destroy(&actual_str);
            kevue_string_destroy(&actual_str_title);
            kevue_string_destroy(&expected_str);
        }
    }
    printf("%s PASSED\n", __func__);
}

void test_string_join(void)
{
    // empty
    String     empty = { 0 };
    StringView comma = StringViewFromLiteral(",");
    StringList strs = { 0 };
    kevue_dyna_append(&strs, empty);
    String str = kevue_string_join(strs, comma);
    assert(kevue_string_is_empty(str));
    kevue_dyna_remove(&strs, 0);

    // single element
    String s1 = String("Hello");
    kevue_dyna_append(&strs, s1);
    str = kevue_string_join(strs, comma);
    assert(memcmp(str.data, "Hello", str.len) == 0);
    kevue_string_destroy(&str);
    kevue_string_destroy(&s1);
    for (i64 i = strs.len - 1; i >= 0; i--) {
        kevue_dyna_remove(&strs, i);
    }

    // concat empty elems
    String s2 = { 0 };
    kevue_dyna_append(&strs, s2);
    kevue_dyna_append(&strs, s2);
    str = kevue_string_join(strs, comma);
    assert(memcmp(str.data, ",", str.len) == 0);
    kevue_string_destroy(&str);
    for (i64 i = strs.len - 1; i >= 0; i--) {
        kevue_dyna_remove(&strs, i);
    }

    // keep separator for empty parts
    String s3 = { 0 };
    String s4 = String("Hello");
    kevue_dyna_append(&strs, s3);
    kevue_dyna_append(&strs, s4);
    kevue_dyna_append(&strs, s3);
    str = kevue_string_join(strs, comma);
    assert(memcmp(str.data, ",Hello,", str.len) == 0);
    kevue_string_destroy(&str);
    kevue_string_destroy(&s4);
    for (i64 i = strs.len - 1; i >= 0; i--) {
        kevue_dyna_remove(&strs, i);
    }
    // normal concat
    String s5 = String("Hello");
    String s6 = String("World");
    kevue_dyna_append(&strs, s5);
    kevue_dyna_append(&strs, s6);
    str = kevue_string_join(strs, comma);
    assert(memcmp(str.data, "Hello,World", str.len) == 0);
    kevue_string_destroy(&str);
    kevue_string_destroy(&s5);
    kevue_string_destroy(&s6);
    for (i64 i = strs.len - 1; i >= 0; i--) {
        kevue_dyna_remove(&strs, i);
    }

    KevueAllocator *ma = kevue_allocator();
    ma->free(strs.ptr, ma->ctx);
    printf("%s PASSED\n", __func__);
}

void test_string_view_from_string(void)
{
    char      *s = "Hello, World";
    String     str = kevue_string_create(s);
    StringView sv = kevue_string_view_from_string(str);
    assert(sv.len == str.len);
    assert(sv.data == str.data);
    kevue_string_destroy(&str);
    printf("%s PASSED\n", __func__);
}

void test_string_view_from_cstring(void)
{
    char      *s = "Hello, World";
    StringView sv = kevue_string_view_from_cstring(s);
    assert(sv.len == strlen(s));
    assert(sv.data == (u8 *)s);
    printf("%s PASSED\n", __func__);
}

void test_string_view_from_buffer(void)
{
    Buffer buf = { 0 };
    kevue_buffer_appendf(&buf, "Hello, World %d times", 42);
    StringView sv = kevue_string_view_from_buffer(buf);
    assert(sv.len == buf.size);
    assert(sv.data == buf.ptr);
    assert(memcmp(sv.data, buf.ptr, sv.len) == 0);
    KevueAllocator *ma = kevue_allocator();
    ma->free(buf.ptr, ma->ctx);
    printf("%s PASSED\n", __func__);
}

void test_string_view_compare(void)
{
    const char *input[] = {
        "",
        "",
        "",
        " ",
        "a",
        "a",
        "a",
        "A",
        "a",
        "b",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abcd",
        "abc",
        "abc",
        "abd",
        "abc",
        "xbc",
        "Hello, World",
        "Hello, World",
        "Hello, World",
        "hello, world",
        "Hello, World1",
        "Hello, World2",
        "Hello, World",
        "Hello, World ",
        " Hello, World",
        "Hello, World",
        "Hello,  World",
        "Hello, World",
        "tab\there",
        "tab\there",
        "tab\there",
        "tab here",
        "\t",
        "\v",
        "line\n",
        "line\r\n",
        " \"Hello, World\"\t\v ",
        " \"Hello, World\"\t\v ",
        " \"Hello, World\"\t\v ",
        " \"Hello, World\"\t\t ",
        "\x01\x02",
        "\x01\x02",
        "\x01\x02",
        "\x01\x03",
        "\x7f",
        "\x7f",
        "\xff",
        "\xff",
        "\xff",
        "\x7f",
        "0",
        "00",
        "a\\b",
        "a\\b",
        "a\\b",
        "a/b",
    };

    const bool expected[] = {
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_compare(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}
void test_string_view_compare_icase(void)
{
    const char *input[] = {
        "",
        "",
        "",
        " ",
        "a",
        "a",
        "a",
        "A",
        "A",
        "a",
        "a",
        "b",
        "abc",
        "ABC",
        "abc",
        "aBc",
        "abc",
        "abcd",
        "ABCD",
        "abc",
        "abc",
        "ABD",
        "abc",
        "XBC",
        "Hello, World",
        "Hello, World",
        "Hello, World",
        "hello, world",
        "Hello, World",
        "HELLO, WORLD",
        "Hello, World1",
        "Hello, World2",
        "Hello, World",
        "Hello, World ",
        " Hello, World",
        "Hello, World",
        "Hello,  World",
        "Hello, World",
        "tab\there",
        "TAB\tHERE",
        "tab\there",
        "TAB HERE",
        "\t",
        "\v",
        "line\n",
        "LINE\r\n",
        " \"Hello, World\"\t\v ",
        " \"HELLO, WORLD\"\t\v ",
        " \"Hello, World\"\t\v ",
        " \"HELLO, WORLD\"\t\t ",
        "\x01\x02",
        "\x01\x02",
        "\x01\x02",
        "\x01\x03",
        "\x7f",
        "\x7f",
        "\xff",
        "\xff",
        "\xff",
        "\x7f",
        "@",
        "`",
        "[",
        "{",
        "@AZ[",
        "@az[",
        "`az{",
        "`AZ{",
        "@",
        "@",
        "a@",
        "A`",
        "Z[",
        "z{",
        "0",
        "00",
        "a\\b",
        "A\\B",
        "a\\b",
        "A/B",
    };
    const bool expected[] = {
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_compare_icase(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_has_suffix(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "bc",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abc",
        "ab",
        "abcabc",
        "bca",
        "Hello, World",
        "World",
        "Hello, World",
        "world",
        "Hello, World ",
        "World",
        "Hello, World",
        " Hello, World",
        "tab\there",
        "\there",
        "tab\there",
        " here",
        "line\r\n",
        "\r\n",
        "line\r\n",
        "\r",
        "\xff\xfe",
        "\xfe",
        "\xff",
        "\x7f",
    };

    const bool expected[] = {
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_has_suffix(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_has_prefix(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "ab",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abc",
        "bc",
        "abcabc",
        "bca",
        "Hello, World",
        "Hello",
        "Hello, World",
        "hello",
        "Hello, World",
        "Hello, World ",
        "tab\there",
        "tab\t",
        "tab\there",
        "tab ",
        "line\r\n",
        "line\r",
        "\xff\xfe",
        "\xff",
        "\xff",
        "\x7f",
        "aaa",
        "aaaa",
        "a\\b",
        "a\\",
    };

    const bool expected[] = {
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_has_prefix(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_trim_suffix(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "bc",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abc",
        "ab",
        "abcabc",
        "abc",
        "aaa",
        "aa",
        "Hello, World",
        "World",
        "Hello, World",
        "world",
        "tab\there",
        "\there",
        "line\r\n",
        "\r\n",
        "line\r\n",
        "\n",
        "\xff\xfe",
        "\xfe",
        "\xff",
        "\x7f",
        "a\\b",
        "\\b",
    };

    const char *expected[] = {
        "",
        "",
        "a",
        "",
        "a",
        "a",
        "",
        "abc",
        "abc",
        "abc",
        "a",
        "Hello, ",
        "Hello, World",
        "tab",
        "line",
        "line\r",
        "\xff",
        "\xff",
        "a",
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        StringView sv_actual = kevue_string_view_trim_suffix(sv1, sv2);
        StringView sv_expected = kevue_string_view_from_cstring(expected[j]);
        assert(kevue_string_view_compare(sv_actual, sv_expected));
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_trim_prefix(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "ab",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abc",
        "bc",
        "abcabc",
        "abc",
        "aaa",
        "aa",
        "Hello, World",
        "Hello, ",
        "Hello, World",
        "hello",
        "tab\there",
        "tab\t",
        "line\r\n",
        "line",
        "\xff\xfe",
        "\xff",
        "\xff",
        "\x7f",
        "a\\b",
        "a\\",
    };

    const char *expected[] = {
        "",
        "",
        "a",
        "",
        "a",
        "c",
        "",
        "abc",
        "abc",
        "abc",
        "a",
        "World",
        "Hello, World",
        "here",
        "\r\n",
        "\xfe",
        "\xff",
        "b",
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        StringView sv_actual = kevue_string_view_trim_prefix(sv1, sv2);
        StringView sv_expected = kevue_string_view_from_cstring(expected[j]);
        assert(kevue_string_view_compare(sv_actual, sv_expected));
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_index(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "a",
        "abc",
        "b",
        "abc",
        "c",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abcabc",
        "abc",
        "abcabc",
        "bca",
        "aaa",
        "aa",
        "aaaa",
        "aa",
        "Hello, World",
        "o",
        "Hello, World",
        "hello",
        "Hello, World",
        "World",
        "tab\there",
        "\t",
        "line\r\n",
        "\r\n",
        "\xff\xfe\xff",
        "\xff",
        "abab",
        "",
        "ababab",
        "bab",
    };

    const int expected[] = {
        0,
        -1,
        0,
        0,
        -1,
        0,
        1,
        2,
        0,
        -1,
        0,
        1,
        0,
        0,
        4,
        -1,
        7,
        3,
        4,
        0,
        0,
        1,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_index(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_last_index(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "a",
        "abc",
        "b",
        "abc",
        "c",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abcabc",
        "abc",
        "abcabc",
        "bca",
        "aaa",
        "aa",
        "aaaa",
        "aa",
        "Hello, World",
        "o",
        "Hello, World",
        "hello",
        "Hello, World",
        "World",
        "tab\there",
        "\t",
        "line\r\n",
        "\r\n",
        "\xff\xfe\xff",
        "\xff",
        "abab",
        "",
        "ababab",
        "bab",
    };

    const int expected[] = {
        0,
        -1,
        1,
        0,
        -1,
        0,
        1,
        2,
        0,
        -1,
        3,
        1,
        1,
        2,
        8,
        -1,
        7,
        3,
        4,
        2,
        4,
        3,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_last_index(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_count(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "a",
        "",
        "abc",
        "",
        "a",
        "a",
        "a",
        "A",
        "abc",
        "abc",
        "abc",
        "abcd",
        "abc",
        "b",
        "abcabc",
        "abc",
        "abcabc",
        "bca",
        "aaa",
        "aa",
        "aaaa",
        "aa",
        "aaaaa",
        "aa",
        "ababab",
        "bab",
        "ababab",
        "ab",
        "abab",
        "aba",
        "xaxax",
        "xax",
        "Hello, World",
        "o",
        "Hello, World",
        "l",
        "Hello, World",
        "hello",
        "a b  c",
        "  ",
        "tab\ta\tb",
        "\t",
        "line\r\nline\r\n",
        "\r\n",
        "cheese",
        "e",
        "five",
        "",
    };

    const int expected[] = {
        1,
        0,
        2,
        4,
        1,
        0,
        1,
        0,
        1,
        2,
        1,
        1,
        2,
        2,
        1,
        3,
        1,
        1,
        2,
        3,
        0,
        1,
        2,
        2,
        3,
        5,
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        assert(kevue_string_view_count(sv1, sv2) == expected[j]);
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_trim_space(void)
{
    const char *input[] = {
        "",
        " ",
        "a",
        " a",
        "a ",
        " a ",
        "a b",
        " a b ",
        "  a  b  ",
        "\t\n\v\f\r ",
        "\t\n a \r\f\v",
        "\xff",
        "a",
        "\xff",
        "\x01 a \x01",
        "\x7f",
    };

    const char *expected[] = {
        "",
        "",
        "a",
        "a",
        "a",
        "a",
        "a b",
        "a b",
        "a  b",
        "",
        "a",
        "\xff",
        "a",
        "\xff",
        "\x01 a \x01",
        "\x7f",
    };
    for (int i = 0; i < sizeof(input) / sizeof(input[0]); i++) {
        StringView sv = kevue_string_view_from_cstring(input[i]);
        StringView sv_actual = kevue_string_view_trim_space(sv);
        StringView sv_expected = kevue_string_view_from_cstring(expected[i]);
        assert(kevue_string_view_compare(sv_actual, sv_expected));
    }
    printf("%s PASSED\n", __func__);
}

void test_string_view_trim_cutset(void)
{
    const char *input[] = {
        "",
        "",
        "",
        "a",
        "abc",
        "",
        "a",
        "a",
        "aaa",
        "a",
        "abc",
        "a",
        "abc",
        "c",
        "abcba",
        "ab",
        "abc",
        "abc",
        "abc",
        "xyz",
        "abc",
        "A",
        "xxhixx",
        "x",
        "xyxhixyx",
        "xy",
        "abcabc",
        "ca",
        "a b",
        "a",
        "  a  ",
        " ",
        "\ta\t",
        "\t",
        "\xff\xfe\xfa\xfe\xff",
        "\xff\xfe",
    };

    const char *trim_left_expected[] = {
        "",
        "",
        "abc",
        "",
        "",
        "bc",
        "abc",
        "cba",
        "",
        "abc",
        "abc",
        "hixx",
        "hixyx",
        "bcabc",
        " b",
        "a  ",
        "a\t",
        "\xfa\xfe\xff",
    };

    const char *trim_right_expected[] = {
        "",
        "",
        "abc",
        "",
        "",
        "abc",
        "ab",
        "abc",
        "",
        "abc",
        "abc",
        "xxhi",
        "xyxhi",
        "abcab",
        "a b",
        "  a",
        "\ta",
        "\xff\xfe\xfa",
    };

    const char *trim_expected[] = {
        "",
        "",
        "abc",
        "",
        "",
        "bc",
        "ab",
        "c",
        "",
        "abc",
        "abc",
        "hi",
        "hi",
        "bcab",
        " b",
        "a",
        "a",
        "\xfa",
    };
    for (int i = 0, j = 0; i + 1 < sizeof(input) / sizeof(input[0]); i += 2, j++) {
        StringView sv1 = kevue_string_view_from_cstring(input[i]);
        StringView sv2 = kevue_string_view_from_cstring(input[i + 1]);
        StringView sv_actual_trim_left = kevue_string_view_trim_left(sv1, sv2);
        StringView sv_expected_trim_left = kevue_string_view_from_cstring(trim_left_expected[j]);
        assert(kevue_string_view_compare(sv_actual_trim_left, sv_expected_trim_left));
        StringView sv_actual_trim_right = kevue_string_view_trim_right(sv1, sv2);
        StringView sv_expected_trim_right = kevue_string_view_from_cstring(trim_right_expected[j]);
        assert(kevue_string_view_compare(sv_actual_trim_right, sv_expected_trim_right));
        StringView sv_actual_trim = kevue_string_view_trim(sv1, sv2);
        StringView sv_expected_trim = kevue_string_view_from_cstring(trim_expected[j]);
        assert(kevue_string_view_compare(sv_actual_trim, sv_expected_trim));
    }
    printf("%s PASSED\n", __func__);
}

void run_tests()
{
    test_string_create();
    test_string_create_macro();
    test_string_createf();
    test_string_createf_macro();
    test_string_from_string_view();
    test_string_copy();
    test_string_copy_empty();
    test_string_to_lower();
    test_string_to_upper();
    test_string_to_title();
    test_string_join();
    test_string_view_from_string();
    test_string_view_from_cstring();
    test_string_view_from_buffer();
    test_string_view_compare();
    test_string_view_compare_icase();
    test_string_view_has_suffix();
    test_string_view_has_prefix();
    test_string_view_trim_suffix();
    test_string_view_trim_prefix();
    test_string_view_index();
    test_string_view_last_index();
    test_string_view_count();
    test_string_view_trim_space();
    test_string_view_trim_cutset();
}

int main()
{
    run_tests();
    return 0;
}
