// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_loader.c — load a BPF program with a userspace-BCF bundle.
 *
 * Usage:
 *   test_loader [--type TYPE] [--per-prog] <prog.bpf.o> [<bundle.bcf-bundle>]
 *
 *   TYPE: a libbpf prog-type name (e.g. classifier, xdp, kprobe). Required
 *         for objects whose ELF section names libbpf can't auto-detect
 *         (e.g. cilium's `2/1` tail-call indices).
 *
 *   --per-prog: per-program kernel oracle. Instead of one whole-object
 *         bpf_object__load (which libbpf aborts at the FIRST failing
 *         program), reopen the object once per program and autoload only
 *         that program, yielding an independent kernel verdict for EVERY
 *         program in a multi-prog .o. Ignores any bundle. Output:
 *         `PERPROG OK|FAIL [i] <name> [errno=N]` + `PERPROG SUMMARY
 *         loaded=x/n`. Always exits 0 (the per-line verdicts are the
 *         result). This is the false-accept ground-truth oracle.
 *
 * Default mode iterates ALL programs in the .o (cilium-style
 * multi-program objects), applies the explicit type if given, attaches
 * the bundle to each program, then loads the entire object via libbpf.
 *
 * Exit code: 0 if bpf_object__load() succeeds (all programs loaded),
 *            non-zero otherwise.
 *
 * Built against the patched libbpf in this tree.
 */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(const char *prog0)
{
	fprintf(stderr,
		"usage: %s [--type TYPE] [--per-prog] <prog.bpf.o> [<bundle.bcf-bundle>]\n",
		prog0);
}

static void *map_file(const char *path, size_t *out_size)
{
	struct stat sb;
	int fd = open(path, O_RDONLY);
	void *p;

	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
		return NULL;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "fstat(%s): %s\n", path, strerror(errno));
		close(fd);
		return NULL;
	}
	p = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap(%s): %s\n", path, strerror(errno));
		return NULL;
	}
	*out_size = sb.st_size;
	return p;
}

/* Map a libbpf prog-type name string to enum bpf_prog_type. Returns
 * BPF_PROG_TYPE_UNSPEC on unknown. Covers the common types we hit in
 * the BCF corpus. */
static enum bpf_prog_type type_by_name(const char *name)
{
	struct {
		const char *name;
		enum bpf_prog_type type;
	} table[] = {
		{ "socket",        BPF_PROG_TYPE_SOCKET_FILTER },
		{ "kprobe",        BPF_PROG_TYPE_KPROBE },
		{ "kretprobe",     BPF_PROG_TYPE_KPROBE },
		{ "classifier",    BPF_PROG_TYPE_SCHED_CLS },
		{ "action",        BPF_PROG_TYPE_SCHED_ACT },
		{ "tracepoint",    BPF_PROG_TYPE_TRACEPOINT },
		{ "raw_tracepoint", BPF_PROG_TYPE_RAW_TRACEPOINT },
		{ "xdp",           BPF_PROG_TYPE_XDP },
		{ "perf_event",    BPF_PROG_TYPE_PERF_EVENT },
		{ "sockops",       BPF_PROG_TYPE_SOCK_OPS },
		{ "sk_skb",        BPF_PROG_TYPE_SK_SKB },
		{ "sk_msg",        BPF_PROG_TYPE_SK_MSG },
		{ "cgroup_skb",    BPF_PROG_TYPE_CGROUP_SKB },
		{ "lwt_in",        BPF_PROG_TYPE_LWT_IN },
		{ "lwt_out",       BPF_PROG_TYPE_LWT_OUT },
		{ "lwt_xmit",      BPF_PROG_TYPE_LWT_XMIT },
		{ "lwt_seg6local", BPF_PROG_TYPE_LWT_SEG6LOCAL },
		{ "fentry",        BPF_PROG_TYPE_TRACING },
		{ "fexit",         BPF_PROG_TYPE_TRACING },
		{ NULL, BPF_PROG_TYPE_UNSPEC },
	};
	for (int i = 0; table[i].name; i++)
		if (strcmp(name, table[i].name) == 0)
			return table[i].type;
	return BPF_PROG_TYPE_UNSPEC;
}

/* Per-program kernel oracle: reopen the object once per program and
 * autoload only that program, so every program in a multi-prog .o gets
 * an independent kernel verifier verdict (libbpf's whole-object load
 * aborts at the first failure, hiding the rest). Bundle-less. */
static int run_per_prog(const char *prog_path, enum bpf_prog_type forced_type, const char *bundle_path)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	char **names = NULL;
	char **secs = NULL;
	int n = 0, cap = 0, i, n_loaded = 0;
	void *bundle = NULL; size_t bundle_size = 0;
	if (bundle_path) bundle = map_file(bundle_path, &bundle_size);

	/* pass 1: enumerate program names + ELF section names (stable
	 * order). The section name is the join key against alivio, which
	 * reports verdicts per ELF section; libbpf is authoritative on
	 * the section↔program relationship (a multi-FUNC section yields
	 * several programs sharing one section name — that asymmetry is
	 * exactly what the scorecard must surface honestly). */
	obj = bpf_object__open_file(prog_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "bpf_object__open_file(%s): %s\n",
			prog_path, strerror(-libbpf_get_error(obj)));
		return 1;
	}
	bpf_object__for_each_program(prog, obj) {
		const char *sn;
		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			names = realloc(names, cap * sizeof(*names));
			secs = realloc(secs, cap * sizeof(*secs));
		}
		names[n] = strdup(bpf_program__name(prog));
		sn = bpf_program__section_name(prog);
		secs[n] = strdup(sn ? sn : "?");
		n++;
	}
	bpf_object__close(obj);
	if (n == 0) {
		fprintf(stderr, "no programs in %s\n", prog_path);
		free(names);
		free(secs);
		return 1;
	}
	printf("programs: %d in object (per-prog mode)\n", n);

	/* Per-program verifier log buffer. Captured at log_level 1 so the
	 * scorecard can tell a *verifier* reject (EACCES, or any reject the
	 * verifier core emitted) apart from a *post-verifier* load failure
	 * (EINVAL after do_check completed — JIT / do_misc_fixups /
	 * fixup_call_args). The latter is NOT a verifier false-accept: the
	 * kernel verifier and alivio (a verifier mirror) agree the program
	 * is safe; the divergence is in a non-verifier kernel stage. */
	const size_t logsz = 16u << 20;
	char *logbuf = malloc(logsz);
	if (!logbuf) {
		fprintf(stderr, "malloc(logbuf) failed\n");
		goto done_free;
	}

	/* pass 2: load each program in isolation */
	for (i = 0; i < n; i++) {
		int idx = 0, fd = -1, lerr;

		obj = bpf_object__open_file(prog_path, NULL);
		if (libbpf_get_error(obj)) {
			printf("PERPROG FAIL [%d] %s open-errno=%ld\n",
			       i, names[i], -libbpf_get_error(obj));
			continue;
		}
		logbuf[0] = '\0';
		bpf_object__for_each_program(prog, obj) {
			if (forced_type != BPF_PROG_TYPE_UNSPEC)
				bpf_program__set_type(prog, forced_type);
			bpf_program__set_autoload(prog, idx == i);
			if (idx == i) {
				bpf_program__set_log_buf(prog, logbuf, logsz);
				bpf_program__set_log_level(prog, 2);
				if (bundle) bpf_program__set_bcf_bundle(prog, bundle, (unsigned)bundle_size);
			}
			idx++;
		}
		lerr = bpf_object__load(obj);
		idx = 0;
		bpf_object__for_each_program(prog, obj) {
			if (idx == i) { fd = bpf_program__fd(prog); break; }
			idx++;
		}
		if (fd >= 0) {
			printf("PERPROG OK   [%d] sec=%s %s\n",
			       i, secs[i], names[i]);
			n_loaded++;
		} else {
			int e = lerr ? -lerr : errno;
			/* Classify (corpus = structurally-valid real eBPF):
			 * by kernel design the verifier core returns -EACCES
			 * for safety rejects; a real well-formed program that
			 * fails with -EINVAL did so in a *post*-verifier pass
			 * (do_misc_fixups / fixup_call_args / JIT) — the
			 * verifier accepted it, so it is NOT a verifier
			 * false-accept. Safety net: if the captured log holds
			 * an unambiguous verifier-core reject phrase, force
			 * VREJECT even on -EINVAL (covers the rare structural
			 * -EINVAL). This only ever downgrades EINVAL→VREJECT,
			 * never the reverse — conservative, never under-counts
			 * a real FA. */
			static const char *vrej_markers[] = {
				"!read_ok", "invalid mem access",
				"invalid access to", "back-edge",
				"jump out of range", "unreachable insn",
				"reserved fields", "leaks addr",
				"Unreleased reference", "math between",
				"pointer arithmetic prohibited",
				"min value is", "max value is",
				"misconfigured", "unknown func",
				"not allowed in", NULL
			};
			const char *kind = "VREJECT";
			if (e == EINVAL) {
				int j, core = 0;
				for (j = 0; vrej_markers[j]; j++)
					if (strstr(logbuf, vrej_markers[j])) {
						core = 1;
						break;
					}
				if (!core)
					kind = "POSTVERIF";
			}
			printf("PERPROG FAIL [%d] sec=%s %s errno=%d kind=%s\n",
			       i, secs[i], names[i], e, kind);
			if (logbuf[0]) fprintf(stderr, "=== LOGBUF [%d] %s ===\n%s\n=== ENDLOG [%d] ===\n", i, names[i], logbuf, i);
		}
		bpf_object__close(obj);
	}
	free(logbuf);
done_free:;
	printf("PERPROG SUMMARY loaded=%d/%d\n", n_loaded, n);
	for (i = 0; i < n; i++) {
		free(names[i]);
		free(secs[i]);
	}
	free(names);
	free(secs);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	const char *type_name = NULL;
	enum bpf_prog_type forced_type = BPF_PROG_TYPE_UNSPEC;
	const char *prog_path = NULL;
	const char *bundle_path = NULL;
	size_t bundle_size = 0;
	void *bundle = NULL;
	int err = 0, n_progs = 0, n_loaded = 0, argi = 1, per_prog = 0;

	/* parse args */
	while (argi < argc) {
		if (strcmp(argv[argi], "--type") == 0) {
			if (argi + 1 >= argc) { usage(argv[0]); return 1; }
			type_name = argv[argi + 1];
			argi += 2;
		} else if (strcmp(argv[argi], "--per-prog") == 0) {
			per_prog = 1;
			argi += 1;
		} else if (strcmp(argv[argi], "-h") == 0
			|| strcmp(argv[argi], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			break;
		}
	}
	if (argi >= argc) { usage(argv[0]); return 1; }
	prog_path = argv[argi++];
	if (argi < argc) bundle_path = argv[argi++];

	if (type_name) {
		forced_type = type_by_name(type_name);
		if (forced_type == BPF_PROG_TYPE_UNSPEC) {
			fprintf(stderr, "unknown --type: %s\n", type_name);
			return 1;
		}
	}

	if (per_prog)
		return run_per_prog(prog_path, forced_type, bundle_path);

	if (bundle_path) {
		bundle = map_file(bundle_path, &bundle_size);
		if (!bundle) return 1;
		printf("bundle: %s (%zu bytes)\n", bundle_path, bundle_size);
	} else {
		printf("bundle: (none)\n");
	}

	obj = bpf_object__open_file(prog_path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open_file(%s): %s\n",
			prog_path, strerror(-err));
		return 1;
	}

	/* iterate ALL programs: set type if forced, attach bundle to each */
	bpf_object__for_each_program(prog, obj) {
		n_progs++;
		if (forced_type != BPF_PROG_TYPE_UNSPEC) {
			err = bpf_program__set_type(prog, forced_type);
			if (err) {
				fprintf(stderr,
					"bpf_program__set_type(%s, %s): %s\n",
					bpf_program__name(prog), type_name,
					strerror(-err));
				goto out;
			}
		}
		if (bundle) {
			err = bpf_program__set_bcf_bundle(prog, bundle,
							  (__u32)bundle_size);
			if (err) {
				fprintf(stderr,
					"bpf_program__set_bcf_bundle(%s): %s\n",
					bpf_program__name(prog), strerror(-err));
				goto out;
			}
		}
	}
	if (n_progs == 0) {
		fprintf(stderr, "no programs in %s\n", prog_path);
		err = -1;
		goto out;
	}
	printf("programs: %d in object\n", n_progs);

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "bpf_object__load: %s (errno=%d)\n",
			strerror(-err), -err);
		goto out;
	}

	/* count successfully-loaded programs (autoload-honoring) */
	bpf_object__for_each_program(prog, obj) {
		int fd = bpf_program__fd(prog);
		if (fd >= 0) n_loaded++;
		printf("program: %s, type=%d, fd=%d\n",
		       bpf_program__name(prog),
		       bpf_program__type(prog), fd);
	}
	printf("SUCCESS: loaded %d/%d program(s)\n", n_loaded, n_progs);
	err = 0;

out:
	bpf_object__close(obj);
	if (bundle)
		munmap(bundle, bundle_size);
	return err ? 1 : 0;
}
