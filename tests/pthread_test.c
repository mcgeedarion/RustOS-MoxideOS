/*
 * pthread_test.c — minimal static musl pthread smoke test.
 *
 * Exercises the exact syscall sequence that today's futex + waitpid
 * fixes enable:
 *
 *   main thread:
 *     pthread_create  → clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS|...)
 *                       musl writes child TID into tid word,
 *                       then FUTEX_WAIT(tid_word, tid)
 *     pthread_join    → FUTEX_WAIT(tid_word, tid) until worker exits
 *
 *   worker thread:
 *     returns (void*)42
 *     do_exit → Arch::clear_child_tid → *tid_word = 0
 *                                     → FUTEX_WAKE(1) on tid_word
 *     main unblocks, checks retval, writes sentinel
 *
 * Output on success:  "PTHREAD_TEST PASS\n"
 * Output on failure:  "PTHREAD_TEST FAIL\n"
 */
#include <pthread.h>
#include <unistd.h>

static void *worker(void *arg)
{
    (void)arg;
    return (void *)42;
}

int main(void)
{
    pthread_t t;
    void     *ret = (void *)0;

    if (pthread_create(&t, (void *)0, worker, (void *)0) != 0) {
        write(STDOUT_FILENO, "PTHREAD_TEST FAIL\n", 18);
        return 1;
    }

    if (pthread_join(t, &ret) != 0) {
        write(STDOUT_FILENO, "PTHREAD_TEST FAIL\n", 18);
        return 1;
    }

    if ((long)ret == 42)
        write(STDOUT_FILENO, "PTHREAD_TEST PASS\n", 18);
    else
        write(STDOUT_FILENO, "PTHREAD_TEST FAIL\n", 18);

    return 0;
}
