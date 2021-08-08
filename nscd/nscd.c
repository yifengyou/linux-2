/* Copyright (c) 1998-2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@suse.de>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* nscd - Name Service Cache Daemon. Caches passwd, group, and hosts.  */

#include <argp.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <paths.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "dbg_log.h"
#include "nscd.h"
#include "selinux.h"
#include "../nss/nsswitch.h"
#include <device-nrs.h>

/* Get libc version number.  */
#include <version.h>

#define PACKAGE _libc_intl_domainname

/* Structure used by main() thread to keep track of the number of
   active threads.  Used to limit how many threads it will create
   and under a shutdown condition to wait till all in-progress
   requests have finished before "turning off the lights".  */

typedef struct
{
  int             num_active;
  pthread_cond_t  thread_exit_cv;
  pthread_mutex_t mutex;
} thread_info_t;

thread_info_t thread_info;

int do_shutdown;
int disabled_passwd;
int disabled_group;
int go_background = 1;

int secure_in_use;
static const char *conffile = _PATH_NSCDCONF;

time_t start_time;

uintptr_t pagesize_m1;

int paranoia;
time_t restart_time;
time_t restart_interval = RESTART_INTERVAL;
const char *oldcwd;
uid_t old_uid;
gid_t old_gid;

static int check_pid (const char *file);
static int write_pid (const char *file);

/* Name and version of program.  */
static void print_version (FILE *stream, struct argp_state *state);
void (*argp_program_version_hook) (FILE *, struct argp_state *) = print_version;

/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] =
{
  { "config-file", 'f', N_("NAME"), 0,
    N_("Read configuration data from NAME") },
  { "debug", 'd', NULL, 0,
    N_("Do not fork and display messages on the current tty") },
  { "nthreads", 't', N_("NUMBER"), 0, N_("Start NUMBER threads") },
  { "shutdown", 'K', NULL, 0, N_("Shut the server down") },
  { "statistic", 'g', NULL, 0, N_("Print current configuration statistic") },
  { "invalidate", 'i', N_("TABLE"), 0,
    N_("Invalidate the specified cache") },
  { "secure", 'S', N_("TABLE,yes"), OPTION_HIDDEN,
    N_("Use separate cache for each user")},
  { NULL, 0, NULL, 0, NULL }
};

/* Short description of program.  */
static const char doc[] = N_("Name Service Cache Daemon.");

/* Prototype for option handler.  */
static error_t parse_opt (int key, char *arg, struct argp_state *state);

/* Data structure to communicate with argp functions.  */
static struct argp argp =
{
  options, parse_opt, NULL, doc,
};

/* True if only statistics are requested.  */
static bool get_stats;

int
main (int argc, char **argv)
{
  int remaining;

  /* Set locale via LC_ALL.  */
  setlocale (LC_ALL, "");
  /* Set the text message domain.  */
  textdomain (PACKAGE);

  /* Determine if the kernel has SELinux support.  */
  nscd_selinux_enabled (&selinux_enabled);

  /* Parse and process arguments.  */
  argp_parse (&argp, argc, argv, 0, &remaining, NULL);

  if (remaining != argc)
    {
      error (0, 0, gettext ("wrong number of arguments"));
      argp_help (&argp, stdout, ARGP_HELP_SEE, program_invocation_short_name);
      exit (EXIT_FAILURE);
    }

  /* Read the configuration file.  */
  if (nscd_parse_file (conffile, dbs) != 0)
    {
      /* We couldn't read the configuration file.  We don't start the
	 server.  */
      dbg_log (_("cannot read configuration file; this is fatal"));
      exit (1);
    }

  /* Do we only get statistics?  */
  if (get_stats)
    /* Does not return.  */
    receive_print_stats ();

  /* Check if we are already running. */
  if (check_pid (_PATH_NSCDPID))
    error (EXIT_FAILURE, 0, _("already running"));

  /* Remember when we started.  */
  start_time = time (NULL);

  /* Determine page size.  */
  pagesize_m1 = getpagesize () - 1;

  /* Behave like a daemon.  */
  if (go_background)
    {
      int i;

      pid_t pid = fork ();
      if (pid == -1)
	error (EXIT_FAILURE, errno, _("cannot fork"));
      if (pid != 0)
	exit (0);

      int nullfd = open (_PATH_DEVNULL, O_RDWR);
      if (nullfd != -1)
	{
	  struct stat64 st;

	  if (fstat64 (nullfd, &st) == 0 && S_ISCHR (st.st_mode) != 0
#if defined DEV_NULL_MAJOR && defined DEV_NULL_MINOR
	      && st.st_rdev == makedev (DEV_NULL_MAJOR, DEV_NULL_MINOR)
#endif
	      )
	    {
	      /* It is the /dev/null special device alright.  */
	      (void) dup2 (nullfd, STDIN_FILENO);
	      (void) dup2 (nullfd, STDOUT_FILENO);
	      (void) dup2 (nullfd, STDERR_FILENO);

	      if (nullfd > 2)
		close (nullfd);
	    }
	  else
	    {
	      /* Ugh, somebody is trying to play a trick on us.  */
	      close (nullfd);
	      nullfd = -1;
	    }
	}
      int min_close_fd = nullfd == -1 ? 0 : STDERR_FILENO + 1;

      DIR *d = opendir ("/proc/self/fd");
      if (d != NULL)
	{
	  struct dirent64 *dirent;
	  int dfdn = dirfd (d);

	  while ((dirent = readdir64 (d)) != NULL)
	    {
	      char *endp;
	      long int fdn = strtol (dirent->d_name, &endp, 10);

	      if (*endp == '\0' && fdn != dfdn && fdn >= min_close_fd)
		close ((int) fdn);
	    }

	  closedir (d);
	}
      else
	for (i = min_close_fd; i < getdtablesize (); i++)
	  close (i);

      pid = fork ();
      if (pid == -1)
	error (EXIT_FAILURE, errno, _("cannot fork"));
      if (pid != 0)
	exit (0);

      setsid ();

      chdir ("/");

      openlog ("nscd", LOG_CONS | LOG_ODELAY, LOG_DAEMON);

      if (write_pid (_PATH_NSCDPID) < 0)
        dbg_log ("%s: %s", _PATH_NSCDPID, strerror (errno));

      if (!init_logfile ())
	dbg_log (_("Could not create log file"));

      /* Ignore job control signals.  */
      signal (SIGTTOU, SIG_IGN);
      signal (SIGTTIN, SIG_IGN);
      signal (SIGTSTP, SIG_IGN);
    }
  else
    /* In foreground mode we are not paranoid.  */
    paranoia = 0;

  /* Start the SELinux AVC.  */
  if (selinux_enabled)
    nscd_avc_init ();

  signal (SIGINT, termination_handler);
  signal (SIGQUIT, termination_handler);
  signal (SIGTERM, termination_handler);
  signal (SIGPIPE, SIG_IGN);

  /* Cleanup files created by a previous 'bind'.  */
  unlink (_PATH_NSCDSOCKET);

  /* Make sure we do not get recursive calls.  */
  __nss_disable_nscd ();

  /* Init databases.  */
  nscd_init ();

  /* Handle incoming requests */
  start_threads ();

  return 0;
}


/* Handle program arguments.  */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'd':
      ++debug_level;
      go_background = 0;
      break;

    case 'f':
      conffile = arg;
      break;

    case 'K':
      if (getuid () != 0)
	error (EXIT_FAILURE, 0, _("Only root is allowed to use this option!"));
      {
	int sock = nscd_open_socket ();
	request_header req;
	ssize_t nbytes;

	if (sock == -1)
	  exit (EXIT_FAILURE);

	req.version = NSCD_VERSION;
	req.type = SHUTDOWN;
	req.key_len = 0;
	nbytes = TEMP_FAILURE_RETRY (write (sock, &req,
					    sizeof (request_header)));
	close (sock);
	exit (nbytes != sizeof (request_header) ? EXIT_FAILURE : EXIT_SUCCESS);
      }

    case 'g':
      get_stats = true;
      break;

    case 'i':
      if (getuid () != 0)
	error (EXIT_FAILURE, 0, _("Only root is allowed to use this option!"));
      else
	{
	  int sock = nscd_open_socket ();

	  if (sock == -1)
	    exit (EXIT_FAILURE);

	  request_header req;
	  ssize_t nbytes;
	  struct iovec iov[2];

	  if (strcmp (arg, "passwd") == 0)
	    req.key_len = sizeof "passwd";
	  else if (strcmp (arg, "group") == 0)
	    req.key_len = sizeof "group";
	  else if (strcmp (arg, "hosts") == 0)
	    req.key_len = sizeof "hosts";
	  else
	    return ARGP_ERR_UNKNOWN;

	  req.version = NSCD_VERSION;
	  req.type = INVALIDATE;

	  iov[0].iov_base = &req;
	  iov[0].iov_len = sizeof (req);
	  iov[1].iov_base = arg;
	  iov[1].iov_len = req.key_len;

	  nbytes = TEMP_FAILURE_RETRY (writev (sock, iov, 2));

	  close (sock);

	  exit (nbytes != iov[0].iov_len + iov[1].iov_len
		? EXIT_FAILURE : EXIT_SUCCESS);
	}

    case 't':
      nthreads = atol (arg);
      break;

    case 'S':
#if 0
      if (strcmp (arg, "passwd,yes") == 0)
	secure_in_use = dbs[pwddb].secure = 1;
      else if (strcmp (arg, "group,yes") == 0)
	secure_in_use = dbs[grpdb].secure = 1;
      else if (strcmp (arg, "hosts,yes") == 0)
	secure_in_use = dbs[hstdb].secure = 1;
#else
      error (0, 0, _("secure services not implemented anymore"));
#endif
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

/* Print the version information.  */
static void
print_version (FILE *stream, struct argp_state *state)
{
  fprintf (stream, "nscd (GNU %s) %s\n", PACKAGE, VERSION);
  fprintf (stream, gettext ("\
Copyright (C) %s Free Software Foundation, Inc.\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
"), "2005");
  fprintf (stream, gettext ("Written by %s.\n"),
	   "Thorsten Kukuk and Ulrich Drepper");
}


/* Create a socket connected to a name.  */
int
nscd_open_socket (void)
{
  struct sockaddr_un addr;
  int sock;

  sock = socket (PF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    return -1;

  addr.sun_family = AF_UNIX;
  assert (sizeof (addr.sun_path) >= sizeof (_PATH_NSCDSOCKET));
  strcpy (addr.sun_path, _PATH_NSCDSOCKET);
  if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      close (sock);
      return -1;
    }

  return sock;
}


/* Cleanup.  */
void
termination_handler (int signum)
{
  close_sockets ();

  /* Clean up the file created by 'bind'.  */
  unlink (_PATH_NSCDSOCKET);

  /* Clean up pid file.  */
  unlink (_PATH_NSCDPID);

  // XXX Terminate threads.

  /* Synchronize memory.  */
  for (int cnt = 0; cnt < lastdb; ++cnt)
    {
      if (!dbs[cnt].enabled)
	continue;

      /* Make sure nobody keeps using the database.  */
      dbs[cnt].head->timestamp = 0;

      if (dbs[cnt].persistent)
	// XXX async OK?
	msync (dbs[cnt].head, dbs[cnt].memsize, MS_ASYNC);
    }

  /* Shutdown the SELinux AVC.  */
  if (selinux_enabled)
    nscd_avc_destroy ();

  _exit (EXIT_SUCCESS);
}

/* Returns 1 if the process in pid file FILE is running, 0 if not.  */
static int
check_pid (const char *file)
{
  FILE *fp;

  fp = fopen (file, "r");
  if (fp)
    {
      pid_t pid;
      int n;

      n = fscanf (fp, "%d", &pid);
      fclose (fp);

      /* If we cannot parse the file default to assuming nscd runs.
	 If the PID is alive, assume it is running.  That all unless
	 the PID is the same as the current process' since tha latter
	 can mean we re-exec.  */
      if ((n != 1 || kill (pid, 0) == 0) && pid != getpid ())
        return 1;
    }

  return 0;
}

/* Write the current process id to the file FILE.
   Returns 0 if successful, -1 if not.  */
static int
write_pid (const char *file)
{
  FILE *fp;

  fp = fopen (file, "w");
  if (fp == NULL)
    return -1;

  fprintf (fp, "%d\n", getpid ());
  if (fflush (fp) || ferror (fp))
    return -1;

  fclose (fp);

  return 0;
}
