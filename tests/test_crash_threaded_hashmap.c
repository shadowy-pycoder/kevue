// Authored by https://www.reddit.com/user/skeeto/
// clang -g3 -fsanitize=thread,undefined -Iinclude -Ilib ./tests/test_crash_threaded_hashmap.c -o ./bin/kevue-crash-test -DDEBUG
#include "../src/allocator.c"
#include "../src/buffer.c"
#include "../src/common.c"
#include "../src/threaded_hashmap.c"

static void *get(void *m)
{
    Buffer *b = kevue_buffer_create(1, &kevue_default_allocator);
    HashMap *hm = (HashMap *)m;
    for (;;) {
        kevue_buffer_reset(b);
        hm->ops->kevue_hm_get(hm, ".", 1, b);
    }
}

int main()
{
    HashMap *m = kevue_hm_threaded_create(&kevue_default_allocator);
    pthread_create(&(pthread_t) {}, NULL, get, m);
    for (long long i = 0;;) {
        char key[32] = {};
        int len = snprintf(key, sizeof(key), "%lld", i++);
        if (!m->ops->kevue_hm_put(m, key, len, ".", 1)) return 0;
    }
}
