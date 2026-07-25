/* Minimal stub for clang -target bpf. Real string ops are clang
 * builtins (__builtin_memcpy / __builtin_memset) or BPF helpers
 * (bpf_strncmp). The only declaration BPF programs in this corpus
 * actually consume from <string.h> is memcpy. */
#ifndef _ALIVIO_STUB_STRING_H
#define _ALIVIO_STUB_STRING_H
typedef unsigned long size_t;
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int   memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
int   strcmp(const char *s1, const char *s2);
int   strncmp(const char *s1, const char *s2, size_t n);
#endif
