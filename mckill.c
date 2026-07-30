#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mckill.skel.h"

#define PIN_DIR   "/sys/fs/bpf/mckill"
#define PIN_EXEC  "exec"
#define PIN_SYS   "syscall"
#define PIN_EXIT  "exit"

/* Strong markers: any one of these identifies a Minecraft Java client. */
static const char *const strong_markers[] = {
	"-Dminecraft.client.jar=",
	"net.fabricmc.loader.impl.launch.knot.KnotClient",
	"org.quiltmc.loader.impl.launch.knot.KnotClient",
	"net.minecraft.client.main.Main",
	"net.minecraft.launchwrapper.Launch",
	"cpw.mods.modlauncher.Launcher",
};

/* Branded launcher: brand property + game/assets dirs. */
static const char *const brand_markers[] = {
	"-Dminecraft.launcher.brand=",
	"--gameDir",
	"--assetsDir",
};

/* Vanilla-ish layout: .minecraft + standard launcher args. */
static const char *const layout_markers[] = {
	".minecraft/",
	"--gameDir",
	"--assetsDir",
	"--assetIndex",
	"--versionType",
};

static int is_java_argv0(const char *cmdline, int n)
{
	static const char java[] = "java";
	const size_t java_n = sizeof(java) - 1;
	int end = 0;

	while (end < n && cmdline[end] != '\0')
		end++;
	if (end < (int)java_n)
		return 0;

	const char *name = cmdline + end - (int)java_n;
	return memcmp(name, java, java_n) == 0 &&
	       (name == cmdline || name[-1] == '/');
}

static int pin_link(struct bpf_link *l, const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
	return bpf_link__pin(l, path);
}

static int mem_has(const char *hay, int n, const char *needle)
{
	int m = (int)strlen(needle);

	if (m <= 0 || m > n)
		return 0;
	for (int i = 0; i + m <= n; i++) {
		if (memcmp(hay + i, needle, (size_t)m) == 0)
			return 1;
	}
	return 0;
}

static int has_all(const char *cmdline, int n, const char *const *needles, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (!mem_has(cmdline, n, needles[i]))
			return 0;
	}
	return 1;
}

static int is_mc_java_cmdline(const char *cmdline, int n)
{
	if (!is_java_argv0(cmdline, n))
		return 0;

	for (size_t i = 0; i < sizeof(strong_markers) / sizeof(strong_markers[0]); i++) {
		if (mem_has(cmdline, n, strong_markers[i]))
			return 1;
	}

	if (has_all(cmdline, n, brand_markers,
		    sizeof(brand_markers) / sizeof(brand_markers[0])))
		return 1;

	return has_all(cmdline, n, layout_markers,
		       sizeof(layout_markers) / sizeof(layout_markers[0]));
}

static void scan_proc(int map_fd)
{
	DIR *d = opendir("/proc");
	if (!d)
		return;

	struct dirent *e;
	char path[64], buf[8192];

	while ((e = readdir(d))) {
		if (!isdigit((unsigned char)e->d_name[0]))
			continue;
		snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
		FILE *f = fopen(path, "rb");
		if (!f)
			continue;
		int n = (int)fread(buf, 1, sizeof(buf), f);
		fclose(f);
		if (n > 0 && is_mc_java_cmdline(buf, n)) {
			uint32_t pid = (uint32_t)atoi(e->d_name);
			uint8_t one = 1;
			bpf_map_update_elem(map_fd, &pid, &one, BPF_ANY);
		}
	}
	closedir(d);
}

static int do_unload(void)
{
	static const char *const names[] = { PIN_EXEC, PIN_SYS, PIN_EXIT };
	char path[256];

	for (int i = 0; i < 3; i++) {
		snprintf(path, sizeof(path), "%s/%s", PIN_DIR, names[i]);
		if (unlink(path) && errno != ENOENT)
			fprintf(stderr, "%s: %s\n", path, strerror(errno));
	}
	rmdir(PIN_DIR);
	fputs("mckill: unloaded\n", stdout);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "unload") == 0)
		return do_unload();

	struct mckill_bpf *skel = mckill_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open/load failed: %s\n", strerror(errno));
		return 1;
	}
	if (mckill_bpf__attach(skel)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		mckill_bpf__destroy(skel);
		return 1;
	}

	scan_proc(bpf_map__fd(skel->maps.tmap));

	mkdir(PIN_DIR, 0700);
	if (pin_link(skel->links.pe, PIN_EXEC) ||
	    pin_link(skel->links.ps, PIN_SYS) ||
	    pin_link(skel->links.px, PIN_EXIT)) {
		fprintf(stderr, "pin failed: %s (already loaded? run 'unload')\n",
			strerror(errno));
		mckill_bpf__destroy(skel);
		return 1;
	}

	mckill_bpf__destroy(skel);
	printf("mckill: armed, pinned at %s\n", PIN_DIR);
	return 0;
}
