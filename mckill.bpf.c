#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGSEGV 11
#define BUF_SIZE        8192
#define JAVA_NAME_LEN   4
#define JAVA_PATH_LEN   6
#define JAVA_SCAN_LIMIT 256
#define MAX_MARKER_LEN  48

enum mc_marker {
	MC0, MC1, MC2, MC3, MC4, MC5, MC6, MC7, MC8, MC9, MC10, MC11,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} tmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[BUF_SIZE]);
} abuf SEC(".maps");

struct search_ctx {
	char *buf;
	enum mc_marker marker;
	int found;
};

/* Plaintext cmdline markers used to identify Minecraft Java clients. */
static const char n0[]  = "-Dminecraft.client.jar=";
static const char n1[]  = "net.fabricmc.loader.impl.launch.knot.KnotClient";
static const char n2[]  = "org.quiltmc.loader.impl.launch.knot.KnotClient";
static const char n3[]  = "net.minecraft.client.main.Main";
static const char n4[]  = "net.minecraft.launchwrapper.Launch";
static const char n5[]  = "cpw.mods.modlauncher.Launcher";
static const char n6[]  = ".minecraft/";
static const char n7[]  = "--gameDir";
static const char n8[]  = "--assetsDir";
static const char n9[]  = "--assetIndex";
static const char n10[] = "--versionType";
static const char n11[] = "-Dminecraft.launcher.brand=";

static __always_inline void select_marker(struct search_ctx *s,
					  enum mc_marker marker)
{
	s->marker = marker;
	s->found = 0;
}

static long jcb(__u32 i, void *vctx)
{
	struct search_ctx *s = vctx;
	char *buf = s->buf;

	i &= BUF_SIZE - 1;
	if (i > BUF_SIZE - JAVA_PATH_LEN)
		return 1;
	if (buf[i] == '\0')
		return 1;

	/* bare "java\0" at start of argv */
	if (i == 0 &&
	    buf[0] == 'j' && buf[1] == 'a' && buf[2] == 'v' && buf[3] == 'a' &&
	    buf[4] == '\0')
		goto found;

	/* ".../java\0" */
	if (buf[i]     == '/' &&
	    buf[i + 1] == 'j' &&
	    buf[i + 2] == 'a' &&
	    buf[i + 3] == 'v' &&
	    buf[i + 4] == 'a' &&
	    buf[i + 5] == '\0')
		goto found;

	return 0;
found:
	s->found = 1;
	return 1;
}

static long mcb(__u32 i, void *vctx)
{
	struct search_ctx *s = vctx;
	char *buf = s->buf;
	const char *needle;
	__u32 needle_len;

	i &= BUF_SIZE - 1;
	switch (s->marker) {
	case MC0:  needle = n0;  needle_len = sizeof(n0)  - 1; break;
	case MC1:  needle = n1;  needle_len = sizeof(n1)  - 1; break;
	case MC2:  needle = n2;  needle_len = sizeof(n2)  - 1; break;
	case MC3:  needle = n3;  needle_len = sizeof(n3)  - 1; break;
	case MC4:  needle = n4;  needle_len = sizeof(n4)  - 1; break;
	case MC5:  needle = n5;  needle_len = sizeof(n5)  - 1; break;
	case MC6:  needle = n6;  needle_len = sizeof(n6)  - 1; break;
	case MC7:  needle = n7;  needle_len = sizeof(n7)  - 1; break;
	case MC8:  needle = n8;  needle_len = sizeof(n8)  - 1; break;
	case MC9:  needle = n9;  needle_len = sizeof(n9)  - 1; break;
	case MC10: needle = n10; needle_len = sizeof(n10) - 1; break;
	case MC11: needle = n11; needle_len = sizeof(n11) - 1; break;
	default:
		return 0;
	}

	if (i > BUF_SIZE - MAX_MARKER_LEN)
		return 1;

#pragma unroll
	for (int j = 0; j < MAX_MARKER_LEN; j++) {
		if (j == (int)needle_len)
			break;
		if (buf[i + j] != needle[j])
			return 0;
	}
	s->found = 1;
	return 1;
}

static __always_inline int has_marker(char *buf, __u32 len,
				      struct search_ctx *sc,
				      enum mc_marker marker,
				      __u32 marker_len)
{
	if (len < marker_len)
		return 0;
	select_marker(sc, marker);
	bpf_loop(len - marker_len + 1, mcb, sc, 0);
	return sc->found;
}

SEC("tp/sched/sched_process_exec")
int pe(void *ctx)
{
	__u32 zero = 0;
	char *buf = bpf_map_lookup_elem(&abuf, &zero);
	if (!buf)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 arg_start = BPF_CORE_READ(task, mm, arg_start);
	__u64 arg_end   = BPF_CORE_READ(task, mm, arg_end);
	if (arg_end <= arg_start)
		return 0;

	__u64 len = arg_end - arg_start;
	if (len > BUF_SIZE)
		len = BUF_SIZE;
	if (bpf_probe_read_user(buf, len, (void *)arg_start) != 0)
		return 0;

	__u32 jn = len >= JAVA_NAME_LEN + 1 ?
		   (__u32)(len - JAVA_NAME_LEN) : 0;
	if (jn > JAVA_SCAN_LIMIT)
		jn = JAVA_SCAN_LIMIT;
	struct search_ctx sc = { .buf = buf, .found = 0 };
	bpf_loop(jn, jcb, &sc, 0);
	if (!sc.found)
		return 0;

	/* sizeof(nX) includes trailing NUL; match length is -1 */
	int strong =
		has_marker(buf, len, &sc, MC0,  sizeof(n0)  - 1) ||
		has_marker(buf, len, &sc, MC1,  sizeof(n1)  - 1) ||
		has_marker(buf, len, &sc, MC2,  sizeof(n2)  - 1) ||
		has_marker(buf, len, &sc, MC3,  sizeof(n3)  - 1) ||
		has_marker(buf, len, &sc, MC4,  sizeof(n4)  - 1) ||
		has_marker(buf, len, &sc, MC5,  sizeof(n5)  - 1);
	int branded =
		has_marker(buf, len, &sc, MC11, sizeof(n11) - 1) &&
		has_marker(buf, len, &sc, MC7,  sizeof(n7)  - 1) &&
		has_marker(buf, len, &sc, MC8,  sizeof(n8)  - 1);
	int layout =
		has_marker(buf, len, &sc, MC6,  sizeof(n6)  - 1) &&
		has_marker(buf, len, &sc, MC7,  sizeof(n7)  - 1) &&
		has_marker(buf, len, &sc, MC8,  sizeof(n8)  - 1) &&
		has_marker(buf, len, &sc, MC9,  sizeof(n9)  - 1) &&
		has_marker(buf, len, &sc, MC10, sizeof(n10) - 1);
	if (!strong && !branded && !layout)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u8 one = 1;
	bpf_map_update_elem(&tmap, &pid, &one, BPF_ANY);
	return 0;
}

SEC("raw_tp/sys_enter")
int ps(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u8 *flagged = bpf_map_lookup_elem(&tmap, &pid);
	if (!flagged)
		return 0;
	bpf_send_signal(SIGSEGV);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int px(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&tmap, &pid);
	return 0;
}
