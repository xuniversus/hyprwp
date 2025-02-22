#include <stdio.h>
#include <stdlib.h>
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
#include "uthash.h"  // Hash table macros

/* ---------------- Configuration Structures ---------------- */
typedef struct {
    char *exe;             // external binary to execute
    char **args;           // array of argument tokens for the binary
    int args_count;        // number of tokens
    char *papers;          // default wallpaper directory
    char *profpapers;   // alternative wallpaper directory
    char *assets;          // asset directory
    char **profmonitors;// array of monitor descriptions triggering alternative wallpapers
    int profmonitors_count;
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

    char *trim = NULL;
    size_t len = 0;
    while (getline(&trim, &len, fp) != -1) {
        char *line = trim;
        while (*line && isspace((unsigned char)*line)) line++;
        if (line[0] == '#' || line[0] == '\0' || line[0] == '\n')
            continue;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        // Remove any trailing newline.
        key = trim_whitespace(key);
        value = trim_whitespace(value);

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
        }
    }
    free(trim);
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

/* ---------------- Monitor Process Hashtable ---------------- */
typedef struct {
    char monitorName[256]; // key
    pid_t pid;
    UT_hash_handle hh;
} monitor_entry_t;

static monitor_entry_t *monitor_table = NULL;

void add_monitor_proc_ht(const char *monitorName, pid_t pid) {
    monitor_entry_t *entry = malloc(sizeof(monitor_entry_t));
    if (!entry) { perror("malloc"); exit(EXIT_FAILURE); }
    snprintf(entry->monitorName, sizeof(entry->monitorName), "%s", monitorName);
    entry->pid = pid;
    HASH_ADD_STR(monitor_table, monitorName, entry);
}

void remove_monitor_proc_ht(const char *monitorName) {
    monitor_entry_t *entry;
    HASH_FIND_STR(monitor_table, monitorName, entry);
    if (entry) {
        HASH_DEL(monitor_table, entry);
        free(entry);
    }
}

int belongs_to_same_group(pid_t pid) {
    pid_t pg = getpgid(pid);
    if (pg == -1) return 0;
    return (pg == getpgid(0));
}

void cleanup_dead_processes(void) {
    monitor_entry_t *entry, *tmp;
    HASH_ITER(hh, monitor_table, entry, tmp) {
        if (kill(entry->pid, 0) != 0 || !belongs_to_same_group(entry->pid)) {
            HASH_DEL(monitor_table, entry);
            free(entry);
        }
    }
}

/* ---------------- Wallpaper Selection ---------------- */
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

/* ---------------- Signal Handling ---------------- */
volatile sig_atomic_t child_died_flag = 0;
void sigchld_handler(int signum) {
    (void)signum;
    child_died_flag = 1;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}

/* ---------------- Monitor Event Parsing ---------------- */
typedef struct {
    char *monitorid;
    char *monitorname;
    char *monitordesc;
} monitor_info_t;
/* Expected format: MONITORID,MONITORNAME,MONITORDESCRIPTION */
int parse_monitoradded_data(char *data, monitor_info_t *info) {
    char *token = strsep(&data, ",");
    if (!token) return -1;
    info->monitorid = token;
    token = strsep(&data, ",");
    if (!token) return -1;
    info->monitorname = token;
    token = strsep(&data, ",");
    if (!token) return -1;
    info->monitordesc = token;
    return 0;
}

/* Check if monitordesc matches any string in the profmonitors array */
int use_profile_wallpapers(const char *monitordesc, Config *cfg) {
    for (int i = 0; i < cfg->profmonitors_count; i++) {
        if (strcmp(monitordesc, cfg->profmonitors[i]) == 0)
            return 1;
    }
    return 0;
}

/* ---------------- Building Child Command Arguments ---------------- */
/* Build an argv array for execvp() by iterating over the config->args tokens.
   Replace any token equal to "monitorid" with info->monitorid and any token equal
   to "assetsdir" with cfg->assets. Then append the chosen wallpaper filename.
   Returns a NULL-terminated argv array. */
char **build_child_argv(const monitor_info_t *info, Config *cfg, const char *wallpaper) {
    char **child_argv = malloc((cfg->args_count + 3) * sizeof(char *));
    if (!child_argv) { perror("malloc"); exit(EXIT_FAILURE); }
    child_argv[0] = cfg->exe;
    child_argv++;
    for (int i = 0; i < cfg->args_count; i++) {
        if (strcmp(cfg->args[i], "monitorid") == 0)
            child_argv[i] = info->monitorid;
        else if (strcmp(cfg->args[i], "monitorname") == 0)
            child_argv[i] = info->monitorname;
        else if (strcmp(cfg->args[i], "monitordesc") == 0)
            child_argv[i] = info->monitordesc;
        else if (strcmp(cfg->args[i], "assetsdir") == 0)
            child_argv[i] = cfg->assets;
        else
            child_argv[i] = cfg->args[i];
    }
    child_argv[cfg->args_count] = (char *)wallpaper;
    child_argv[cfg->args_count + 1] = NULL;
    child_argv--;
    return child_argv;
}

/* ---------------- Event Handling ---------------- */
/* Each event is in the format: EVENT>>DATA */
void handle_line(char *line, Config *cfg) {
    char *delim = strstr(line, ">>");
    if (!delim) return;
    *delim = '\0';
    char *data = delim + 2;
    if (strcmp(line, "monitoraddedv2") == 0) {
        monitor_info_t info = {0};
        if (parse_monitoradded_data(data, &info) != 0) {
            fprintf(stderr, "Invalid monitoraddedv2 data\n");
            return;
        }
        const char *wallpaper_dir = cfg->papers;
        if (use_profile_wallpapers(info.monitordesc, cfg) && cfg->profpapers)
            wallpaper_dir = cfg->profpapers;
        char *wallpaper = choose_random_wallpaper(wallpaper_dir);
        if (!wallpaper) {
            fprintf(stderr, "No wallpaper found in directory %s\n", wallpaper_dir);
            return;
        }
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            free(wallpaper);
            return;
        }
        if (pid == 0) {
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
                perror("prctl");
                exit(EXIT_FAILURE);
            }
            if (getppid() == 1)
                exit(EXIT_FAILURE);
            /* Redirect stdout to /dev/null */
            FILE *devnull = fopen("/dev/null", "w");
            if (devnull) {
                dup2(fileno(devnull), STDOUT_FILENO);
                fclose(devnull);
            }
            char **child_argv = build_child_argv(&info, cfg, wallpaper);
            execvp(child_argv[0], child_argv);
            perror("execvp");
            free(child_argv);
            exit(EXIT_FAILURE);
        }
        add_monitor_proc_ht(info.monitorname, pid);
        free(wallpaper);
    } else if (strcmp(line, "monitorremoved") == 0) {
        char *monitorname = data;
        monitor_entry_t *entry;
        HASH_FIND_STR(monitor_table, monitorname, entry);
        if (entry) {
            if (kill(entry->pid, 0) == 0 && belongs_to_same_group(entry->pid))
                kill(entry->pid, SIGTERM);
            remove_monitor_proc_ht(monitorname);
        }
    }
    /* Ignore other events */
}

/* ---------------- Main ---------------- */
int main(int argc, char *argv[]) {
    const char *config_file = "config.txt";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (++i < argc)
                config_file = argv[i];
            else { fprintf(stderr, "Missing filename for --config\n"); exit(EXIT_FAILURE); }
        }
    }
    Config *cfg = read_config(config_file);
    if (!cfg) { fprintf(stderr, "Failed to read config\n"); exit(EXIT_FAILURE); }
    if (!cfg->exe || !cfg->args || cfg->args_count == 0 || !cfg->papers || !cfg->assets) {
        fprintf(stderr, "Config missing required keys\n");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }
    /* profpapers is optional */
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
        // Depending on requirements, you might want to exit or continue
    }
    free(exe_path);

    srand(time(NULL));

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        free_config(cfg);
        exit(EXIT_FAILURE);
    }

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

    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, sock_fp) != -1) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) > 0)
            handle_line(line, cfg);
        if (child_died_flag) { cleanup_dead_processes(); child_died_flag = 0; }
    }
    free(line);
    fclose(sock_fp);
    free_config(cfg);
    return 0;
}
