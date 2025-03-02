#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/prctl.h>

// ---------------- Configuration Structures ----------------
typedef struct {
    char *exe;             // external binary to execute
    char **args;           // array of argument tokens for the binary
    int args_count;        // number of tokens
    char *papers;          // default wallpaper directory
    char *profpapers;      // alternative wallpaper directory
    char *assets;          // asset directory (needs to be passed as assetsdir)
    char **profmonitors;   // monitor descriptions triggering alternative wallpapers
    int profmonitors_count;
    int timer;
} Config;

/* ---------------- Bracketed List Parser ---------------- */
/* Parses a string of the form: [ "token1" "token2" ... ]
   Returns an allocated array of strings (each token allocated with strdup)
   and sets *count to the number of tokens. */
char **parse_list(const char *value, int *count) {
    if (!value) { *count = 0; return NULL; }
    int capacity = 4;
    char **tokens = malloc(capacity * sizeof(char *));
    if (!tokens) { *count = 0; return NULL; }
    int num = 0;
    const char *p = value;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        char *token = NULL;
        if (*p == '\"') {
            p++; // skip opening quote
            const char *start = p;
            while (*p && *p != '\"') p++;
            token = strndup(start, p - start);
            if (*p == '\"') p++; // skip closing quote
        } else {
            const char *start = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            token = strndup(start, p - start);
        }
        if (token) {
            if (num >= capacity) {
                capacity *= 2;
                char **tmp = realloc(tokens, capacity * sizeof(char *));
                if (!tmp) { perror("realloc"); break; }
                tokens = tmp;
            }
            tokens[num++] = token;
        }
    }
    *count = num;
    return tokens;
}

/* ---------------- Simple Config Parser ---------------- */
char *trim_whitespace(char *str) {
    while (*str && isspace((unsigned char)*str))
        str++;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        *end-- = '\0';
    return str;
}

Config *read_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen config");
        return NULL;
    }
    Config *cfg = calloc(1, sizeof(Config));
    if (!cfg) { perror("calloc"); fclose(fp); return NULL; }

    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        char *trim = line;
        while (*trim && isspace((unsigned char)*trim)) trim++;
        if (trim[0] == '#' || trim[0] == '\0' || trim[0] == '\n')
            continue;
        char *eq = strchr(trim, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim_whitespace(trim);
        char *value = trim_whitespace(eq + 1);
        if (strcmp(key, "exe") == 0) {
            cfg->exe = strdup(value);
        } else if (strcmp(key, "args") == 0) {
            cfg->args = parse_list(value, &cfg->args_count);
        } else if (strcmp(key, "papers") == 0) {
            cfg->papers = strdup(value);
        } else if (strcmp(key, "profpapers") == 0) {
            cfg->profpapers = strdup(value);
        } else if (strcmp(key, "assets") == 0) {
            cfg->assets = strdup(value);
        } else if (strcmp(key, "profmonitors") == 0) {
            cfg->profmonitors = parse_list(value, &cfg->profmonitors_count);
        } else if (strcmp(key, "timer") == 0) {
            cfg->timer = atoi(value);
        }
    }
    free(line);
    fclose(fp);
    return cfg;
}

void free_config(Config *cfg) {
    if (!cfg) return;
    free(cfg->exe);
    if (cfg->args) {
        for (int i = 0; i < cfg->args_count; i++)
            free(cfg->args[i]);
        free(cfg->args);
    }
    free(cfg->papers);
    free(cfg->profpapers);
    free(cfg->assets);
    if (cfg->profmonitors) {
        for (int i = 0; i < cfg->profmonitors_count; i++)
            free(cfg->profmonitors[i]);
        free(cfg->profmonitors);
    }
    free(cfg);
}

/* ---------------- Random Wallpaper Selection ---------------- */
/* Returns a random wallpaper file (full path) from the given directory. */
char *choose_random_wallpaper(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) { perror("opendir"); return NULL; }
    struct dirent *entry;
    char **files = NULL;
    size_t count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        size_t len = strlen(dirpath) + strlen(entry->d_name) + 2;
        char *fullpath = malloc(len);
        if (!fullpath) continue;
        snprintf(fullpath, len, "%s/%s", dirpath, entry->d_name);
        char **tmp = realloc(files, (count + 1) * sizeof(char *));
        if (!tmp) { free(fullpath); continue; }
        files = tmp;
        files[count++] = fullpath;
    }
    closedir(dir);
    if (count == 0) { free(files); return NULL; }
    int idx = rand() % count;
    char *result = strdup(files[idx]);
    for (size_t i = 0; i < count; i++) free(files[i]);
    free(files);
    return result;
}

/* Check if monitordesc matches any string in the profmonitors array.
   Returns 1 if it does (and if a profpapers directory is set), else 0. */
bool use_profile_wallpapers(const char *monitordesc, Config *cfg) {
    if (!cfg->profpapers)
        return false;
    for (int i = 0; i < cfg->profmonitors_count; i++) {
        if (strcmp(monitordesc, cfg->profmonitors[i]) == 0)
            return true;
    }
    return false;
}

/* ---------------- Monitor Data Structures ---------------- */
/* For each monitor we store its name and the chosen wallpaper. */
typedef struct {
    char *name;
    char *wallpaper;
    char *monitordesc;
} MonitorEntry;

typedef struct {
    MonitorEntry **entries;
    int count;
    int capacity;
} MonitorArray;

void init_monitor_array(MonitorArray *ma) {
    ma->count = 0;
    ma->capacity = 4;
    ma->entries = malloc(ma->capacity * sizeof(MonitorEntry *));
    if (!ma->entries) { perror("malloc"); exit(EXIT_FAILURE); }
}

int find_monitor_index(MonitorArray *ma, const char *name) {
    for (int i = 0; i < ma->count; i++) {
        if (strcmp(ma->entries[i]->name, name) == 0)
            return i;
    }
    return -1;
}

/* Adds a monitor entry. If monitordesc is provided, use it to determine the wallpaper directory.
   For bootstrapped monitors, monitordesc can be the same as name. */
inline bool add_monitor_entry(MonitorArray *ma, const char *name, const char *monitordesc, Config *cfg) {
    if (strcmp(name, "FALLBACK") == 0 || find_monitor_index(ma, name) != -1)
        return false; // already present

    const char *wallpaper_dir = cfg->papers;
    if (use_profile_wallpapers(monitordesc, cfg))
        wallpaper_dir = cfg->profpapers;

    char *wallpaper = choose_random_wallpaper(wallpaper_dir);
    if (!wallpaper) {
        fprintf(stderr, "No wallpaper found in directory %s for monitor %s\n", wallpaper_dir, name);
        return false;
    }

    MonitorEntry *entry = malloc(sizeof(MonitorEntry));
    if (!entry) { perror("malloc"); exit(EXIT_FAILURE); }
    entry->name = strdup(name);
    entry->monitordesc = strdup(monitordesc);
    entry->wallpaper = wallpaper; // allocated by choose_random_wallpaper

    if (ma->count == ma->capacity) {
        ma->capacity *= 2;
        MonitorEntry **tmp = realloc(ma->entries, ma->capacity * sizeof(MonitorEntry *));
        if (!tmp) { perror("realloc"); exit(EXIT_FAILURE); }
        ma->entries = tmp;
    }
    ma->entries[ma->count++] = entry;
    return true;
}

inline bool remove_monitor_entry(MonitorArray *ma, const char *name) {
    int idx = find_monitor_index(ma, name);
    if (idx == -1)
        return false;
    free(ma->entries[idx]->name);
    free(ma->entries[idx]->monitordesc);
    free(ma->entries[idx]->wallpaper);
    free(ma->entries[idx]);
    for (int i = idx; i < ma->count - 1; i++) {
        ma->entries[i] = ma->entries[i+1];
    }
    ma->count--;
    return true;
}

void free_monitor_array(MonitorArray *ma) {
    for (int i = 0; i < ma->count; i++) {
        free(ma->entries[i]->name);
        free(ma->entries[i]->monitordesc);
        free(ma->entries[i]->wallpaper);
        free(ma->entries[i]);
    }
    free(ma->entries);
}

/* ---------------- Monitor Event Parsing ---------------- */
typedef struct {
    char *monitorid;
    char *monitorname;
    char *monitordesc;
} monitor_info_t;
/* Expected format: MONITORID,MONITORNAME,MONITORDESCRIPTION */
bool parse_monitoradded_data(char *data, monitor_info_t *info) {
    char *token = strsep(&data, ",");
    if (!token) return false;
    info->monitorid = token;
    token = strsep(&data, ",");
    if (!token) return false;
    info->monitorname = token;
    token = strsep(&data, ",");
    if (!token) return false;
    info->monitordesc = token;
    return true;
}

/* ---------------- Global Child Process Handling ---------------- */
volatile pid_t child_pid = -1;

void sigchld_handler(int signum) {
    (void)signum;
    child_pid = -1;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

/* Build argv for execvp:
   Start with cfg->exe, then the tokens from cfg->args (with substitution for "assetsdir"),
   then for every monitor in the array, append:
     "--screen-root", monitor name, "--bg", chosen wallpaper.
   Returns a NULL-terminated argv array.
*/
char **build_child_argv(Config *cfg, MonitorArray *ma) {
    int total = 2 + cfg->args_count + ma->count * 4;  // exe + base args + extra + NULL
    if (cfg->assets) total += 2;
    char **argv = malloc(total * sizeof(char *));
    if (!argv) { perror("malloc"); exit(EXIT_FAILURE); }
    int idx = 0;
    argv[idx++] = cfg->exe;
    if (cfg->assets) {
        argv[idx++] = "--assets-dir";
        argv[idx++] = cfg->assets;
    }
    for (int i = 0; i < cfg->args_count; i++)
        argv[idx++] = cfg->args[i];
    for (int i = 0; i < ma->count; i++) {
        argv[idx++] = "--screen-root";
        argv[idx++] = ma->entries[i]->name;
        argv[idx++] = "--bg";
        argv[idx++] = ma->entries[i]->wallpaper;
    }
    argv[idx] = NULL;
    return argv;
}

/* Restart the child process with the current monitor list.
   If a process is already running, kill it and wait for it to exit.
*/
void restart_child_process(Config *cfg, MonitorArray *ma) {
    if (child_pid > 0) {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
    }
    if (ma->count > 0) {
        char **child_argv = build_child_argv(cfg, ma);
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            free(child_argv);
            return;
        }
        if (pid == 0) {
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
                perror("prctl");
                exit(EXIT_FAILURE);
            }
            execvp(child_argv[0], child_argv);
            perror("execvp");
            free(child_argv);
            exit(EXIT_FAILURE);
        }
        child_pid = pid;
        free(child_argv);
    }
}

/* ---------------- Event Handling ---------------- */
/* Each event is in the format: EVENT>>DATA */
bool handle_line(char *line, Config *cfg, MonitorArray *ma) {
    char *delim = strstr(line, ">>");
    if (!delim) return false;
    *delim = '\0';
    char *data = delim + 2;
    if (strcmp(line, "monitoraddedv2") == 0) {
        monitor_info_t info = {0};
        if (!parse_monitoradded_data(data, &info)) {
            fprintf(stderr, "Invalid monitoraddedv2 data\n");
            return false;
        }
        return add_monitor_entry(ma, info.monitorname, info.monitordesc, cfg);
    } else if (strcmp(line, "monitorremoved") == 0) {
        return remove_monitor_entry(ma, data);
    }
    /* Ignore other events */
    return false;
}

/* ---------------- Bootstrap Monitor from Positional Argument ---------------- */
/* For bootstrapped monitors, we assume the monitor description equals the monitor name */
inline void bootstrap_monitor(const char *monitor_name, Config *cfg, MonitorArray *ma) {
    add_monitor_entry(ma, monitor_name, monitor_name, cfg);
}

/* ---------------- Main ---------------- */
int main(int argc, char *argv[]) {
    const char *config_file = "config.txt";
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--config") == 0) {
            if (++i < argc)
                config_file = argv[i];
            else {
                fprintf(stderr, "Missing filename for --config\n");
                exit(EXIT_FAILURE);
            }
        } else break;
        i++;
    }
    Config *cfg = read_config(config_file);
    if (!cfg) { fprintf(stderr, "Failed to read config\n"); exit(EXIT_FAILURE); }
    if (!cfg->exe || !cfg->args || cfg->args_count == 0 || !cfg->papers) {
        fprintf(stderr, "Config missing required keys\n");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    // Change working directory to the directory of the executable
    char *exe_path = strdup(cfg->exe);
    if (!exe_path) {
        perror("strdup");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    char *dir_path = dirname(exe_path);
    if (chdir(dir_path) != 0) {
        perror("chdir to exe directory");
        free(exe_path);
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    free(exe_path);
    srand(time(NULL));

    // Initialize monitor array and add any monitors provided as extra positional arguments.
    MonitorArray monitor_array;
    init_monitor_array(&monitor_array);
    while (i < argc) {
        bootstrap_monitor(trim_whitespace(argv[i]), cfg, &monitor_array);
        i++;
    }
    // If we have any monitors at startup, start the child process.
    restart_child_process(cfg, &monitor_array);

    // Set up SIGCHLD handler.
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }

    // Set up socket connection.
    char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    char *hypr_signature = getenv("HYPRLAND_INSTANCE_SIGNATURE");
    if (!runtime_dir || !hypr_signature) {
        fprintf(stderr, "Missing environment variables for socket connection\n");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path),
                 "%s/hypr/%s/.socket2.sock", runtime_dir, hypr_signature)
        >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Socket path is too long\n");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); free_config(cfg); exit(EXIT_FAILURE); }
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    FILE *sock_fp = fdopen(sockfd, "r");
    if (!sock_fp) { perror("fdopen"); close(sockfd); free_config(cfg); exit(EXIT_FAILURE); }

    time_t last_update_time = time(NULL);
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, sock_fp) != -1) {
        // Check if enough time has passed to update wallpapers.
        line[strcspn(line, "\n")] = '\0';
        time_t current_time = time(NULL);
        bool res = false;
        if (strlen(line) > 0)
            res = handle_line(line, cfg, &monitor_array);
        if (cfg->timer > 0 && difftime(current_time, last_update_time) >= cfg->timer * 60) {
            for (int j = 0; j < monitor_array.count; j++) {
                MonitorEntry *entry = monitor_array.entries[j];
                free(entry->wallpaper);
                const char *wallpaper_dir = cfg->papers;
                if (use_profile_wallpapers(entry->monitordesc, cfg))
                    wallpaper_dir = cfg->profpapers;
                entry->wallpaper = choose_random_wallpaper(wallpaper_dir);
            }
            restart_child_process(cfg, &monitor_array);
            last_update_time = current_time;
        } else if (child_pid < 0 || res)
            restart_child_process(cfg, &monitor_array);
    }
    free(line);
    fclose(sock_fp);
    // Clean up: terminate child process and free resources.
    if (child_pid > 0) {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
    }
    free_monitor_array(&monitor_array);
    free_config(cfg);
    return 0;
}
