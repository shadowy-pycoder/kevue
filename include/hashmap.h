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
 * @file hashmap.h
 * @brief Hash map API.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <allocator.h>
#include <buffer.h>

/**
 * @typedef HashMap
 * @brief Opaque hashmap type.
 */
typedef struct HashMap HashMap;

typedef struct HashMapOps {
    /**
     * Destroys a hashmap instance.
     *
     * Releases all resources associated with the hashmap.
     *
     * @param hm  Hashmap to destroy.
     */
    void (*kevue_hm_destroy)(HashMap *hm);
    /**
     * Retrieves a value associated with a key.
     *
     * If the key exists, the value is written into @p buf.
     *
     * @param hm       Hashmap instance.
     * @param key      Pointer to key data.
     * @param key_len  Length of @p key in bytes.
     * @param buf      Buffer to receive the value.
     *
     * @return true on success, false on failure.
     *
     * @note The existing contents of @p buf may be overwritten or partially
     * replaced depending on the implementation.
     */
    bool (*kevue_hm_get)(HashMap *hm, const void *key, size_t key_len, Buffer *buf);
    /**
     * Inserts or replaces a key-value pair in the hashmap.
     *
     * The key and value data are copied into internal storage.
     *
     * @param hm       Hashmap instance.
     * @param key      Pointer to key data.
     * @param key_len  Length of @p key in bytes.
     * @param val      Pointer to value data.
     * @param val_len  Length of @p val in bytes.
     *
     * @return true if the key is put successfuly, false otherwise.
     *
     * @note returns false if hashmap is full
     */
    bool (*kevue_hm_put)(HashMap *hm, const void *key, size_t key_len, const void *val, size_t val_len);
    /**
     * Removes a key-value pair from the hashmap.
     *
     * @param hm       Hashmap instance.
     * @param key      Pointer to key data.
     * @param key_len  Length of @p key in bytes.
     *
     * @return true if the key was removed, false if it was not found.
     */
    bool (*kevue_hm_del)(HashMap *hm, const void *key, size_t key_len);
    /**
     * @brief Sets the hash seed used by the hashmap.
     *
     * @param hm    Hashmap instance.
     * @param seed  Hash seed value.
     *
     * @note The caller is responsible for providing a suitably
     *       unpredictable seed (e.g. from a system RNG) if
     *       resistance to hash-flooding attacks is required.
     *
     * @note Must be called before inserting any entries.
     * @note Changing the seed after use requires a full rehash.
     */
    void (*kevue_hm_seed)(HashMap *hm, uint64_t seed);
    /**
     * @brief Retrieves the number of entries stored in the hashmap.
     *
     * Returns the current count of key–value pairs present in @p hm.
     *
     * @param hm  Hashmap instance.
     *
     * @return Number of entries currently stored in the hashmap.
     *
     * @note The returned value reflects the logical size of the hashmap,
     * not its internal capacity.
     * @note This operation is O(1).
     */
    uint64_t (*kevue_hm_len)(HashMap *hm);
    /**
     * Retrieves all stored items.
     *
     * Serializes all key–value pairs in the hashmap into @p buf.
     *
     * @param hm   Hashmap instance.
     * @param buf  Buffer to receive serialized items.
     *
     * @return true on success, false on failure.
     *
     * @note The existing contents of @p buf may be overwritten or partially
     * replaced depending on the implementation.
     * @note This operation is O(n) in the number of entries.
     */
    bool (*kevue_hm_items)(HashMap *hm, Buffer *buf);

    /**
     * Retrieves all keys.
     *
     * Serializes all keys in the hashmap into @p buf.
     *
     * @param hm   Hashmap instance.
     * @param buf  Buffer to receive serialized keys.
     *
     * @return true on success, false on failure.
     *
     * @note The existing contents of @p buf may be overwritten or partially
     * replaced depending on the implementation.
     * @note This operation is O(n) in the number of entries.
     */
    bool (*kevue_hm_keys)(HashMap *hm, Buffer *buf);

    /**
     * Retrieves all values.
     *
     * Serializes all values in the hashmap into @p buf.
     *
     * @param hm   Hashmap instance.
     * @param buf  Buffer to receive serialized values.
     *
     * @return true on success, false on failure.
     *
     * @note The existing contents of @p buf may be overwritten or partially
     * replaced depending on the implementation.
     * @note This operation is O(n) in the number of entries.
     */
    bool (*kevue_hm_values)(HashMap *hm, Buffer *buf);
} HashMapOps;

typedef HashMap *(*kevue_hm_create)(uint64_t seed, KevueAllocator *ma);

struct HashMap {
    const HashMapOps *ops;
    void             *internal;
};

/**
 * @def HashMapTS(KT, VT)
 * @brief Type-safe hashmap wrapper.
 *
 * Provides compile-time type checking for keys and values using a union.
 * Inspired by techniques described in:
 * https://danielchasehooper.com/posts/typechecked-generic-c-data-structures/
 *
 * @param KT  Key type.
 * @param VT  Value type.
 *
 * @note Type safety is enforced at compile time using macro-based
 *       expressions. No runtime checks are performed.
 *
 * @note Type-safe macros rely on the HashMapTS instance storing the
 *       declared key and value types (ktype, vtype) solely for
 *       compile-time validation.
 */
#define HashMapTS(KT, VT) \
    union {               \
        HashMap *hm;      \
        KT      *ktype;   \
        VT      *vtype;   \
    }

/**
 * @def map_value_ptr(x)
 * @brief Obtains a pointer suitable for hashmap storage.
 *
 * If @p x is already a pointer, it is returned unchanged.
 * Otherwise, the address of @p x is returned.
 *
 * @warning Argument must be an lvalue.
 */
#define map_value_ptr(x)   \
    _Generic((x),          \
        char *: (x),       \
        const char *: (x), \
        default: &(x))

/**
 * @def kevue_hmts_create(ma)
 * @brief Creates a type-safe hashmap wrapper.
 *
 ** @param hm_create_fn  Hashmap creation function.
 *                      Must have signature:
 *                      HashMap *(*)(KevueAllocator *)
 *
 * @param ma  KevueAllocator to use.
 *
 * @return Initialized HashMapTS instance.
 */
#define kevue_hmts_create(hm_create_fn, ma) { .hm = ((kevue_hm_create)(hm_create_fn))(ma) }

/**
 * @def kevue_hmts_destroy(hmts)
 * @brief Destroys a type-safe hashmap instance.
 *
 * Calls the underlying hashmap implementation's destroy function and
 * releases all resources associated with the hashmap.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 *
 * @note After this call, @p hmts->hm becomes invalid and must not be used.
 */
#define kevue_hmts_destroy(hmts) (hmts)->hm->ops->kevue_hm_destroy((hmts)->hm)

/**
 * @def kevue_hmts_put(hmts, key, key_len, val, val_len)
 * @brief Inserts or replaces a key-value pair with compile-time type checking.
 *
 * Inserts a key-value pair into the hashmap. If the key already exists,
 * its value is replaced.
 *
 * This macro performs a **compile-time type check** on @p key and @p val
 * by forcing the compiler to validate that their types match the
 * key/value types declared in the HashMapTS instance.
 *
 * No runtime overhead is introduced by this check.
 *
 * @param hmts     Pointer to a HashMapTS instance.
 * @param key      Key value (must match the declared key type).
 * @param key_len  Size of the key in bytes.
 * @param val      Value to store (must match the declared value type).
 * @param val_len  Size of the value in bytes.
 *
 * @return true on success, false on failure.
 *
 * @note Type mismatches result in a compile-time error or warning.
 * @note Key and value data are copied into internal storage.
 * @note returns false if hashmap is full
 */
#define kevue_hmts_put(hmts, key, key_len, val, val_len)                                                               \
    (hmts)->hm->ops->kevue_hm_put((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len), \
        ((1 ? &(val) : (hmts)->vtype) ? map_value_ptr((val)) : NULL), (val_len))

/**
 * @def kevue_hmts_get(hmts, key, key_len, buf)
 * @brief Retrieves a value using a typed key.
 *
 * Looks up a key in the hashmap and writes the associated value
 * into the provided buffer.
 *
 * This macro enforces **compile-time checking** of the key type
 * against the HashMapTS declared key type.
 *
 * @param hmts     Pointer to a HashMapTS instance.
 * @param key      Key value (must match the declared key type).
 * @param key_len  Size of the key in bytes.
 * @param buf      Buffer to receive the value.
 *
 * @return true if the key exists, false otherwise.
 */
#define kevue_hmts_get(hmts, key, key_len, buf) \
    (hmts)->hm->ops->kevue_hm_get((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len), (buf))

/**
 * @def kevue_hmts_del(hmts, key, key_len)
 * @brief Removes a key-value pair using a typed key.
 *
 * Deletes the entry associated with the given key from the hashmap.
 *
 * This macro enforces **compile-time checking** of the key type
 * against the HashMapTS declared key type.
 *
 * @param hmts     Pointer to a HashMapTS instance.
 * @param key      Key value (must match the declared key type).
 * @param key_len  Size of the key in bytes.
 *
 * @return true if the key was removed, false if it was not found.
 */
#define kevue_hmts_del(hmts, key, key_len) \
    (hmts)->hm->ops->kevue_hm_del((hmts)->hm, ((1 ? &(key) : (hmts)->ktype) ? map_value_ptr((key)) : NULL), (key_len))

/**
 * @def kevue_hmts_seed(hmts, seed)
 * @brief Sets the hash seed used by a type-safe hashmap.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 * @param seed  Hash seed value.
 *
 * @note The caller is responsible for providing a suitably
 *       unpredictable seed (e.g. from a system RNG) if
 *       resistance to hash-flooding attacks is required.
 *
 * @note Must be called before inserting any entries.
 * @note Changing the seed after use requires a full rehash.
 */
#define kevue_hmts_seed(hmts, seed) (hmts)->hm->ops->kevue_hm_seed((hmts)->hm, (seed))

/**
 * @def kevue_hmts_len
 * @brief Returns the number of entries in a type-safe hashmap.
 *
 * Returns the current count of key–value pairs present in @p hmts.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 *
 * @return Number of entries currently stored in the hashmap.
 */
#define kevue_hmts_len(hmts) (hmts)->hm->ops->kevue_hm_len((hmts)->hm)

/**
 * @def kevue_hmts_items
 * @brief Retrieves all stored items from a type-safe hashmap.
 *
 * Serializes all key–value pairs from the underlying hashmap
 * into the provided buffer.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 * @param buf   Buffer to receive serialized items.
 *
 * @return true on success, false on failure.
 */
#define kevue_hmts_items(hmts, buf) \
    (hmts)->hm->ops->kevue_hm_items((hmts)->hm, (buf))

/**
 * @def kevue_hmts_keys
 * @brief Retrieves all keys from a type-safe hashmap.
 *
 * Serializes all keys from the underlying hashmap
 * into the provided buffer.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 * @param buf   Buffer to receive serialized keys.
 *
 * @return true on success, false on failure.
 */
#define kevue_hmts_keys(hmts, buf) \
    (hmts)->hm->ops->kevue_hm_keys((hmts)->hm, (buf))

/**
 * @def kevue_hmts_values
 * @brief Retrieves all values from a type-safe hashmap.
 *
 * Serializes all values from the underlying hashmap
 * into the provided buffer.
 *
 * @param hmts  Pointer to a HashMapTS instance.
 * @param buf   Buffer to receive serialized values.
 *
 * @return true on success, false on failure.
 */
#define kevue_hmts_values(hmts, buf) \
    (hmts)->hm->ops->kevue_hm_values((hmts)->hm, (buf))
