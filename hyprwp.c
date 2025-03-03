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
                if (!tmp) { perror("realloc"); free(token); break; }
                tokens = tmp;
            }
            tokens[num++] = token;
        } else { perror("strndup"); break; }
    }
    *count = num;
    return tokens;
}

/* ---------------- Simple Config Parser ---------------- */
char *trim_whitespace(char *str) {
    if (!str) return str;
    while (*str && isspace((unsigned char)*str))
        str++;
    if (*str == '\0') return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        *end-- = '\0';
    return str;
}

void free_plist(char **list, const int count) {
    for (int i = 0; i < count; i++)
        free(list[i]);
    free(list);
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
            free(cfg->exe);
            cfg->exe = strdup(value);
        } else if (strcmp(key, "args") == 0) {
            free_plist(cfg->args, cfg->args_count);
            cfg->args = parse_list(value, &cfg->args_count);
        } else if (strcmp(key, "papers") == 0) {
            free(cfg->papers);
            cfg->papers = strdup(value);
        } else if (strcmp(key, "profpapers") == 0) {
            free(cfg->profpapers);
            cfg->profpapers = strdup(value);
        } else if (strcmp(key, "assets") == 0) {
            free(cfg->assets);
            cfg->assets = strdup(value);
        } else if (strcmp(key, "profmonitors") == 0) {
            free_plist(cfg->profmonitors, cfg->profmonitors_count);
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
    if (cfg->args)
        free_plist(cfg->args, cfg->args_count);
    free(cfg->papers);
    free(cfg->profpapers);
    free(cfg->assets);
    if (cfg->profmonitors)
        free_plist(cfg->profmonitors, cfg->profmonitors_count);
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
        if (!tmp) { perror("realloc"); free(fullpath); break; }
        files = tmp;
        files[count++] = fullpath;
    }
    closedir(dir);
    if (count == 0) { free(files); return NULL; }
    int idx = rand() % count;
    char *result = strdup(files[idx]);
    free_plist(files, count);
    return result;
}

/* Check if monitordesc matches any string in the profmonitors array.
   Returns true if it does (and if a profpapers directory is set), else 0. */
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
    if (!ma->entries) { perror("malloc"); }
}

int find_monitor_index(MonitorArray *ma, const char *name) {
    for (int i = 0; i < ma->count; i++) {
        if (strcmp(ma->entries[i]->name, name) == 0)
            return i;
    }
    return -1;
}

/* Adds a monitor entry. If monitordesc is provided, use it to determine the wallpaper directory.
   For bootstrapped monitors, monitordesc can be the same as name.
   Returns true on success, false otherwise. */
bool add_monitor_entry(MonitorArray *ma, const char *name, const char *monitordesc, Config *cfg) {
    if (strcmp(name, "FALLBACK") == 0 || find_monitor_index(ma, name) != -1)
        return false; // already present

    const char *wallpaper_dir = cfg->papers;
    if (use_profile_wallpapers(monitordesc, cfg))
        wallpaper_dir = cfg->profpapers;

    MonitorEntry *entry = malloc(sizeof(MonitorEntry));
    if (!entry) { perror("malloc"); return false; }

    entry->wallpaper = choose_random_wallpaper(wallpaper_dir);
    if (!entry->wallpaper) {
        fprintf(stderr, "No wallpaper found in directory %s for monitor %s\n", wallpaper_dir, name);
        free(entry);
        return false;
    }
    entry->name = strdup(name);
    entry->monitordesc = strdup(monitordesc);
    if (!entry->name || !entry->monitordesc) {
        perror("malloc");
        free(entry->name);
        free(entry->monitordesc);
        free(entry->wallpaper);
        free(entry);
        return false;
    }

    if (ma->count == ma->capacity) {
        ma->capacity *= 2;
        MonitorEntry **tmp = realloc(ma->entries, ma->capacity * sizeof(MonitorEntry *));
        if (!tmp) {
            perror("realloc");
            ma->capacity /= 2;
            free(entry->name);
            free(entry->monitordesc);
            free(entry->wallpaper);
            free(entry);
            return false;
        }
        ma->entries = tmp;
    }
    ma->entries[ma->count++] = entry;
    return true;
}

bool remove_monitor_entry(MonitorArray *ma, const char *name) {
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
    if (!argv) { perror("malloc"); return NULL; }
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
        if (!child_argv) { perror("no child args"); return; }
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            free(child_argv);
            return;
        }
        if (pid == 0) {
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
                perror("prctl");
                free(child_argv);
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
void bootstrap_monitor(const char *monitor_name, Config *cfg, MonitorArray *ma) {
    add_monitor_entry(ma, monitor_name, monitor_name, cfg);
}

/* ---------------- Main ---------------- */
int main(int argc, char *argv[]) {
    int ret = EXIT_FAILURE; // Default to fail if exit
    const char *config_file = "config.txt";
    Config *cfg = NULL;
    MonitorArray monitor_array;
    char *exe_path = NULL;
    struct sockaddr_un addr;
    int sockfd = -1;
    FILE *sock_fp = NULL;
    char *line = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (++i < argc)
                config_file = argv[i];
            else { fprintf(stderr, "Missing filename for --config\n"); goto cleanup; }
        } else break;
    }
    cfg = read_config(config_file);
    if (!cfg) { fprintf(stderr, "Failed to read config\n"); goto cleanup; }
    if (!cfg->exe || !cfg->args || cfg->args_count == 0 || !cfg->papers) {
        fprintf(stderr, "Config missing required keys\n"); goto cleanup;
    }
    // Change working directory to the directory of the executable
    exe_path = strdup(cfg->exe);
    if (!exe_path) { perror("strdup"); goto cleanup; }
    if (chdir(dirname(exe_path)) != 0) { perror("chdir to exe directory"); goto cleanup; }
    free(exe_path);
    exe_path = NULL;
    srand(time(NULL));

    // Initialize monitor array.
    init_monitor_array(&monitor_array);
    if (!monitor_array.entries) { perror("monitor array uninitialized"); goto cleanup; }

    char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    char *hypr_signature = getenv("HYPRLAND_INSTANCE_SIGNATURE");
    // --- Retrieve monitors from second UNIX socket ---
    {
        if (!runtime_dir || !hypr_signature) {
            fprintf(stderr, "Missing environment variables for socket connection\n");
            goto cleanup;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (snprintf(addr.sun_path, sizeof(addr.sun_path),
                     "%s/hypr/%s/.socket.sock", runtime_dir, hypr_signature)
            >= sizeof(addr.sun_path)) {
            fprintf(stderr, "Socket path too long for monitor query\n");
            goto cleanup;
        }
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) { perror("socket (monitor query)"); goto cleanup; }
        if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect (monitor query)");
            goto cleanup;
        }
        sock_fp = fdopen(sockfd, "r+");
        if (!sock_fp) { perror("fdopen (monitor query)"); goto cleanup; }

        // Write command to retrieve monitors.
        fprintf(sock_fp, "/monitors\n");
        fflush(sock_fp);

        // Read the entire response into an array of lines.
        char **lines = NULL;
        int lines_count = 0, lines_capacity = 10;
        lines = malloc(lines_capacity * sizeof(char *));
        if (!lines) { perror("malloc"); goto cleanup; }
        char *mon_line = NULL;
        size_t mon_len = 0;
        while (getline(&mon_line, &mon_len, sock_fp) != -1) {
            mon_line[strcspn(mon_line, "\n")] = '\0';
            char *trim = trim_whitespace(mon_line);
            if (strlen(trim) == 0)
                continue;
            else if (strncmp(trim, "Monitor", 7) == 0 || strncmp(trim, "description:", 12) == 0) {
                line = strdup(trim);
                if (!line) {
                    perror("strdup");
                    free(mon_line);
                    free_plist(lines, lines_count);
                    goto cleanup;
                }
                if (lines_count >= lines_capacity) {
                    lines_capacity *= 2;
                    char **tmp = realloc(lines, lines_capacity * sizeof(char *));
                    if (!tmp) {
                        perror("realloc");
                        free(mon_line);
                        free_plist(lines, lines_count);
                        goto cleanup;
                    }
                    lines = tmp;
                }
                lines[lines_count++] = line;
            }
        }
        free(mon_line);
        fclose(sock_fp);
        sock_fp = NULL;

        // Parse lines to retrieve monitors.
        for (int idx = 0; idx < lines_count; idx++) {
            line = lines[idx];
            if (strncmp(line, "Monitor", 7) == 0) {
                // Skip the "Monitor" prefix and any leading whitespace.
                char *p = line + 7;
                while (*p && isspace((unsigned char)*p))
                    p++;
                char *name_start = p;
                // Move until whitespace or '(' is encountered.
                while (*p && !isspace((unsigned char)*p) && *p != '(')
                    p++;
                size_t name_len = p - name_start;
                char *monitor_name = malloc(name_len + 1);
                if (!monitor_name) {
                    perror("malloc monitor_name");
                    free_plist(lines, lines_count);
                    goto cleanup;
                }
                strncpy(monitor_name, name_start, name_len);
                monitor_name[name_len] = '\0';
                // Process description from the next line if available.
                char *description = strdup("");
                if (!description) {
                    perror("malloc description");
                    free_plist(lines, lines_count);
                    free(monitor_name);
                    goto cleanup;
                }
                if (idx + 1 < lines_count) {
                    line = lines[idx+1];
                    if (strncmp(line, "description:", 12) == 0) {
                        char *desc = line + 12;
                        desc = trim_whitespace(desc);
                        free(description);
                        description = strdup(desc);
                        if (!description) {
                            perror("malloc description");
                            free_plist(lines, lines_count);
                            free(monitor_name);
                            goto cleanup;
                        }
                        idx++; // skip the description line
                    }
                }
                add_monitor_entry(&monitor_array, monitor_name, description, cfg);
                free(monitor_name);
                free(description);
            }
        }
        free_plist(lines, lines_count);
    }
    // --- End monitor query ---

    // If we have any monitors at startup, start the child process.
    restart_child_process(cfg, &monitor_array);

    // Set up SIGCHLD handler.
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        goto cleanup;
    }

    // Set up socket connection for events using .socket2.sock.
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path),
                 "%s/hypr/%s/.socket2.sock", runtime_dir, hypr_signature)
        >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Socket path is too long\n");
        goto cleanup;
    }
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); goto cleanup; }
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); goto cleanup;
    }
    sock_fp = fdopen(sockfd, "r");
    if (!sock_fp) { perror("fdopen"); goto cleanup; }

    time_t last_update_time = time(NULL);
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
                const char *wallpaper_dir = cfg->papers;
                if (use_profile_wallpapers(entry->monitordesc, cfg))
                    wallpaper_dir = cfg->profpapers;
                char *tmp = choose_random_wallpaper(wallpaper_dir);
                if (!tmp) {
                    fprintf(stderr, "No wallpaper found in directory %s for monitor %s\n", wallpaper_dir, entry->name);
                    break;
                }
                free(entry->wallpaper);
                entry->wallpaper = tmp;
            }
            restart_child_process(cfg, &monitor_array);
            last_update_time = current_time;
        } else if (child_pid < 0 || res)
            restart_child_process(cfg, &monitor_array);
    }
    ret = EXIT_SUCCESS; // if reached end, success

cleanup:
    free(line);
    free(exe_path);
    if (sock_fp)
        fclose(sock_fp);
    else if (sockfd != -1)
        close(sockfd);
    // Clean up: terminate child process and free resources.
    if (child_pid > 0) {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
    }
    free_monitor_array(&monitor_array);
    free_config(cfg);
    return ret;
}
