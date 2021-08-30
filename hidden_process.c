// Copyright (C) 2015-2021, Wazuh Inc.

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#define     OS_SIZE_1024    1024
#define     OS_SIZE_2048    2048
#define     MAX_PID         32768
#define     PROC            0      
#define     PID             1
#define     TASK            2

#define     ROOTKIT_ALERT   "INFO: "
#define     SYSTEM_CRIT     "WARN: "

/* Global variables */
int noproc;
int proc_pid_found;

/* Print result */
void notify_rk(char *header, char *msg)
{

    char current_time[32];
    struct tm* to;
    time_t t;
    t = time(NULL);
    to = localtime(&t);
    strftime(current_time, sizeof(current_time), "%Y/%m/%d-%H:%M:%S", to);

    printf("%s: %s[%s]\n", current_time, header, msg);
    return;
}

char *get_process_name(int pid)
{
    FILE *fp;
    char path[2048];
    char command[2048];

    sprintf(command, "cat /proc/%d/cmdline", pid);
    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == NULL) {
        //printf("Failed to run command\n" );
        //exit(1);
        return NULL;
    }

    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path), fp) != NULL) {
        //printf("%s", path);
        pclose(fp);
        return path;
    }

    /* close */
    pclose(fp);
    return NULL;
}
/* Check if a file exists */
int is_file(char *file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Check if 'file' is present on 'dir' using readdir */
int isfile_ondir(const char *file, const char *dir)
{
    DIR *dp = NULL;
    struct dirent *entry = NULL;
    dp = opendir(dir);

    if (!dp) {
        return (0);
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, file) == 0) {
            closedir(dp);
            return (1);
        }
    }

    closedir(dp);
    return (0);
}

/* If /proc is mounted, check to see if the pid is present */
int proc_read(int pid)
{
    char dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(dir, OS_SIZE_1024, "%d", pid);
    if (isfile_ondir(dir, "/proc")) {
        return (1);
    }
    return (0);
}

/* If /proc is mounted, check to see if the pid is present */
int proc_opendir(int pid)
{
    char dir[OS_SIZE_1024 + 1];
    DIR *dp = NULL;

    if (noproc) {
        return (0);
    }
    
    dp  = opendir("/proc");
    if (!dp) {
        return 0;
    }
    closedir(dp);
    
    snprintf(dir, OS_SIZE_1024, "/proc/%d", pid);
    dp  = opendir(dir);
    if (!dp) {
        return 0;
    }
    closedir(dp);

    return (1);
}

/* If /proc is mounted, check to see if the pid is present there */
int proc_stat(int pid)
{
    char proc_dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(proc_dir, OS_SIZE_1024, "%s/%d", "/proc", pid);

    if (is_file(proc_dir)) {
        return (1);
    }

    return (0);
}

/* Check all the available PIDs for hidden stuff */
void loop_all_pids(const char *ps, pid_t max_pid, int *_errors, int *_total)
{
    int _kill0 = 0;
    int _kill1 = 0;
    int _gsid0 = 0;
    int _gsid1 = 0;
    int _gpid0 = 0;
    int _gpid1 = 0;
    int _ps0 = -1;
    int _proc_stat  = 0;
    int _proc_read  = 0;
    int _proc_opendir = 0;

    pid_t i = 1;
    pid_t my_pid;

    char command[OS_SIZE_1024 + 64];

    my_pid = getpid();

    for (;; i++) {
        //printf("LOOP %d\n", i);
        if ((i <= 0) || (i > max_pid)) {
            break;
        }

        (*_total)++;

        _kill0 = 0;
        _kill1 = 0;
        _gsid0 = 0;
        _gsid1 = 0;
        _gpid0 = 0;
        _gpid1 = 0;
        _ps0 = -1;

        /* kill test */
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) { //send signal to every process in the process group of the calling process
            //errno == ESRCH means that process does not exist
            _kill0 = 1;
        }

        /* getsid test */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {//return the session ID of the calling process.
            _gsid0 = 1;
        }

        /* getpgid test */
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {//return the process group ID of the calling process
            _gpid0 = 1;
        }

        /* /proc test */
        _proc_stat = proc_stat(i); // check that /proc/pid exist
        _proc_read = proc_read(i); // check that pid is exist inside /proc
        _proc_opendir = proc_opendir(i); //check that can open directory

        /* If PID does not exist, move on */
        if (!_kill0 && !_gsid0 && !_gpid0 &&
                !_proc_stat && !_proc_read && !_proc_opendir) {
            continue;
        }

        /* Ignore our own pid */
        if (i == my_pid) {
            continue;
        }

        /* Check the number of errors */
        if ((*_errors) > 15) {
            char op_msg[OS_SIZE_1024 + 1];
            snprintf(op_msg, OS_SIZE_1024, "Excessive number of hidden processes"
                     ". It maybe a false-positive or "
                     "something really bad is going on.");
            notify_rk(SYSTEM_CRIT, op_msg);
            return;
        }

        /* Check if the process appears in ps(1) output */
        if (*ps) {
            snprintf(command, sizeof(command), "%s -p %d > /dev/null 2>&1", ps, (int)i);//pidlist
            _ps0 = 0;
            if (system(command) == 0) {
                _ps0 = 1;
            }
        }

        /* If we are run in the context of OSSEC-HIDS, sleep here (no rush) */
// #ifdef OSSECHIDS
// #ifdef WIN32
//         Sleep(rootcheck.tsleep);
// #else
//         struct timeval timeout = {0, rootcheck.tsleep * 1000};
  //       select(0, NULL, NULL, NULL, &timeout);
// #endif
// #endif

        /* Everything fine, move on */
        if (_ps0 && _kill0 && _gsid0 && _gpid0 && _proc_stat && _proc_read) {
            continue;
        }

        /*
         * If our kill or getsid system call got the PID but ps(1) did not,
         * find out if the PID is deleted (not used anymore)
         */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {
            _gsid1 = 1;
        }
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) {
            _kill1 = 1;
        }
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {
            _gpid1 = 1;
        }

        _proc_stat = proc_stat(i);
        _proc_read = proc_read(i);
        _proc_opendir = proc_opendir(i);

        /* If it matches, process was terminated in the meantime, so move on */
        if (!_gsid1 && !_kill1 && !_gpid1 && !_proc_stat &&
                !_proc_read && !_proc_opendir) {
            continue;
        }

//#ifdef AIX
        /* Ignore AIX wait and sched programs */
        if (_gsid0 == _gsid1 &&
                _kill0 == _kill1 &&
                _gpid0 == _gpid1 &&
                _ps0 == 1 &&
                _gsid0 == 1 &&
                _kill0 == 0) {
            /* The wait and sched programs do not respond to kill 0.
             * So if everything else finds it, including ps, getpid, getsid,
             * but not kill, we can safely ignore on AIX.
             * A malicious program would specially try to hide from ps.
             */
            continue;
        }
//#endif

        if (_gsid0 == _gsid1 &&
                _kill0 == _kill1 &&
                _gsid0 != _kill0) {
            /* If kill worked, but getsid and getpgid did not, it may
             * be a defunct process -- ignore.
             */
            if (! (_kill0 == 1 && _gsid0 == 0 && _gpid0 == 0 && _gsid1 == 0) ) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "kill (%d) or getsid (%d). Possible kernel-level"
                         " rootkit.", (int)i, get_process_name((int)i), _kill0, _gsid0);
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_kill1 != _gsid1 ||
                   _gpid1 != _kill1 ||
                   _gpid1 != _gsid1) {
            /* See defunct process comment above */
            if (! (_kill1 == 1 && _gsid1 == 0 && _gpid0 == 0) ) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "kill (%d), getsid (%d) or getpgid. Possible "
                         "kernel-level rootkit.", (int)i, get_process_name((int)i), _kill1, _gsid1);
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_proc_read != _proc_stat  ||
                   _proc_read != _proc_opendir ||
                   _proc_stat != _kill1) {
            /* Check if the pid is a thread (not showing in /proc */
            if (!noproc && !check_rc_readproc((int)i)) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "/proc. Possible kernel level rootkit.", (int)i, get_process_name((int)i));
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_gsid1 && _kill1 && !_ps0) {
            /* checking if the pid is a thread (not showing on ps */
            if (!check_rc_readproc((int)i)) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "ps. Possible trojaned version installed.",
                         (int)i, get_process_name((int)i));
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        }
    }
}

/* Scan the whole filesystem looking for possible issues */
void check_rc_pids()
{
    int _total = 0;
    int _errors = 0;

    char ps[OS_SIZE_1024 + 1];

    char proc_0[] = "/proc";
    char proc_1[] = "/proc/1";

    pid_t max_pid = MAX_PID;
    noproc = 1;

    /* Checking where ps is */
    memset(ps, '\0', OS_SIZE_1024 + 1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if (!is_file(ps)) {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if (!is_file(ps)) {
            ps[0] = '\0';
        }
    }

    /* Proc is mounted */
    if (is_file(proc_0) && is_file(proc_1)) {
        noproc = 0;
    }

    loop_all_pids(ps, max_pid, &_errors, &_total);

    if (_errors == 0) {
        char op_msg[OS_SIZE_2048];
        snprintf(op_msg, OS_SIZE_2048, "No hidden process by Kernel-level "
                 "rootkits.\n      %s is not trojaned. "
                 "Analyzed %d processes.", ps, _total);
        notify_rk(ROOTKIT_ALERT, op_msg);
    }

    return;
}

/////////////////
int read_proc_file(const char *file_name, const char *pid, int position)
{
    struct stat statbuf;

    if (lstat(file_name, &statbuf) < 0) {
        return (-1);
    }

    /* If directory, read the directory */
    if (S_ISDIR(statbuf.st_mode)) {
        return (read_proc_dir(file_name, pid, position));
    }

    return (0);
}

int read_proc_dir(const char *dir_name, const char *pid, int position)
{
    DIR *dp;
    struct dirent *entry = NULL;

    if ((dir_name == NULL) || (strlen(dir_name) > PATH_MAX)) {
        //mterror(ARGV0, "Invalid directory given");
        return (-1);
    }

    /* Open the directory */
    dp = opendir(dir_name);
    if (!dp) {
        return (0);
    }

    while ((entry = readdir(dp)) != NULL) {
        char f_name[PATH_MAX + 2];

        /* Ignore . and ..  */
        if (strcmp(entry->d_name, ".")  == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (position == PROC) {
            char *tmp_str;

            tmp_str = entry->d_name;
            while (*tmp_str != '\0') {
                if (!isdigit((int)*tmp_str)) {
                    break;
                }
                tmp_str++;
            }

            if (*tmp_str != '\0') {
                continue;
            }

            snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
            read_proc_file(f_name, pid, position + 1);
        } else if (position == PID) {
            if (strcmp(entry->d_name, "task") == 0) {
                snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
                read_proc_file(f_name, pid, position + 1);
            }
        } else if (position == TASK) {
            /* Check under proc/pid/task/lwp */
            if (strcmp(entry->d_name, pid) == 0) {
                proc_pid_found = 1;
                break;
            }
        } else {
            break;
        }
    }

    closedir(dp);

    return (0);
}

/*  Read the /proc directory (if present) and check if it can find
 *  the given pid (as a pid or as a thread)
 */
int check_rc_readproc(int pid)
{
    char char_pid[32];

    proc_pid_found = 0;

    /* NL threads */
    snprintf(char_pid, 31, "/proc/.%d", pid);
    if (is_file(char_pid)) {
        return (1);
    }

    snprintf(char_pid, 31, "%d", pid);
    read_proc_dir("/proc", char_pid, PROC);

    return (proc_pid_found);
}
/////////////////
//#else
// void check_rc_pids()
// {
//     return;
// }
//#endif

void main(int argc, char *argv[])
{
    printf("This is the start of the process monitoring...\n");
    if(argc == 1)
    {
        check_rc_pids();
    }
    else if(argc == 2)
    {
        if(atoi(argv[1]) > 0 && atoi(argv[1]) < 60000)
        {
            while(1)
            {
                check_rc_pids();
                printf("Sleeping a while...\n");
                sleep(atoi(argv[1]));
            }
        }
        else
        {
            printf("Run error. Please ask to developer...\n");
        }
        
    }
    else
    {
        printf("Run error. Please ask to developer...\n");
    }
    
    
}