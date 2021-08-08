/* Inner loops of cache daemon.
   Copyright (C) 1998-2003, 2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1998.

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

#include <alloca.h>
#include <assert.h>
#include <atomic.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libintl.h>
#include <pthread.h>
#include <pwd.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifdef HAVE_EPOLL
# include <sys/epoll.h>
#endif
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "nscd.h"
#include "dbg_log.h"
#include "selinux.h"


/* Number of bytes of data we initially reserve for each hash table bucket.  */
#define DEFAULT_DATASIZE_PER_BUCKET 1024


/* Wrapper functions with error checking for standard functions.  */
extern void *xmalloc (size_t n);
extern void *xcalloc (size_t n, size_t s);
extern void *xrealloc (void *o, size_t n);

/* Support to run nscd as an unprivileged user */
const char *server_user;
static uid_t server_uid;
static gid_t server_gid;
const char *stat_user;
uid_t stat_uid;
static gid_t *server_groups;
#ifndef NGROUPS
# define NGROUPS 32
#endif
static int server_ngroups;

static pthread_attr_t attr;

static void begin_drop_privileges (void);
static void finish_drop_privileges (void);

/* Map request type to a string.  */
const char *serv2str[LASTREQ] =
{
  [GETPWBYNAME] = "GETPWBYNAME",
  [GETPWBYUID] = "GETPWBYUID",
  [GETGRBYNAME] = "GETGRBYNAME",
  [GETGRBYGID] = "GETGRBYGID",
  [GETHOSTBYNAME] = "GETHOSTBYNAME",
  [GETHOSTBYNAMEv6] = "GETHOSTBYNAMEv6",
  [GETHOSTBYADDR] = "GETHOSTBYADDR",
  [GETHOSTBYADDRv6] = "GETHOSTBYADDRv6",
  [SHUTDOWN] = "SHUTDOWN",
  [GETSTAT] = "GETSTAT",
  [INVALIDATE] = "INVALIDATE",
  [GETFDPW] = "GETFDPW",
  [GETFDGR] = "GETFDGR",
  [GETFDHST] = "GETFDHST",
  [GETAI] = "GETAI",
  [INITGROUPS] = "INITGROUPS"
};

/* The control data structures for the services.  */
struct database_dyn dbs[lastdb] =
{
  [pwddb] = {
    .lock = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP,
    .enabled = 0,
    .check_file = 1,
    .persistent = 0,
    .shared = 0,
    .filename = "/etc/passwd",
    .db_filename = _PATH_NSCD_PASSWD_DB,
    .disabled_iov = &pwd_iov_disabled,
    .postimeout = 3600,
    .negtimeout = 20,
    .wr_fd = -1,
    .ro_fd = -1,
    .mmap_used = false
  },
  [grpdb] = {
    .lock = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP,
    .enabled = 0,
    .check_file = 1,
    .persistent = 0,
    .shared = 0,
    .filename = "/etc/group",
    .db_filename = _PATH_NSCD_GROUP_DB,
    .disabled_iov = &grp_iov_disabled,
    .postimeout = 3600,
    .negtimeout = 60,
    .wr_fd = -1,
    .ro_fd = -1,
    .mmap_used = false
  },
  [hstdb] = {
    .lock = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP,
    .enabled = 0,
    .check_file = 1,
    .persistent = 0,
    .shared = 0,
    .filename = "/etc/hosts",
    .db_filename = _PATH_NSCD_HOSTS_DB,
    .disabled_iov = &hst_iov_disabled,
    .postimeout = 3600,
    .negtimeout = 20,
    .wr_fd = -1,
    .ro_fd = -1,
    .mmap_used = false
  }
};


/* Mapping of request type to database.  */
static struct database_dyn *const serv2db[LASTREQ] =
{
  [GETPWBYNAME] = &dbs[pwddb],
  [GETPWBYUID] = &dbs[pwddb],
  [GETGRBYNAME] = &dbs[grpdb],
  [GETGRBYGID] = &dbs[grpdb],
  [GETHOSTBYNAME] = &dbs[hstdb],
  [GETHOSTBYNAMEv6] = &dbs[hstdb],
  [GETHOSTBYADDR] = &dbs[hstdb],
  [GETHOSTBYADDRv6] = &dbs[hstdb],
  [GETFDPW] = &dbs[pwddb],
  [GETFDGR] = &dbs[grpdb],
  [GETFDHST] = &dbs[hstdb],
  [GETAI] = &dbs[hstdb],
  [INITGROUPS] = &dbs[grpdb]
};


/* Number of seconds between two cache pruning runs.  */
#define CACHE_PRUNE_INTERVAL	15


/* Initial number of threads to use.  */
int nthreads = -1;
/* Maximum number of threads to use.  */
int max_nthreads = 32;

/* Socket for incoming connections.  */
static int sock;

/* Number of times clients had to wait.  */
unsigned long int client_queued;


ssize_t
writeall (int fd, const void *buf, size_t len)
{
  size_t n = len;
  ssize_t ret;
  do
    {
      ret = TEMP_FAILURE_RETRY (write (fd, buf, n));
      if (ret <= 0)
	break;
      buf = (const char *) buf + ret;
      n -= ret;
    }
  while (n > 0);
  return ret < 0 ? ret : len - n;
}


/* Initialize database information structures.  */
void
nscd_init (void)
{
  /* Secure mode and unprivileged mode are incompatible */
  if (server_user != NULL && secure_in_use)
    {
      dbg_log (_("Cannot run nscd in secure mode as unprivileged user"));
      exit (1);
    }

  /* Look up unprivileged uid/gid/groups before we start listening on the
     socket  */
  if (server_user != NULL)
    begin_drop_privileges ();

  if (nthreads == -1)
    /* No configuration for this value, assume a default.  */
    nthreads = 2 * lastdb;

  for (size_t cnt = 0; cnt < lastdb; ++cnt)
    if (dbs[cnt].enabled)
      {
	pthread_rwlock_init (&dbs[cnt].lock, NULL);
	pthread_mutex_init (&dbs[cnt].memlock, NULL);

	if (dbs[cnt].persistent)
	  {
	    /* Try to open the appropriate file on disk.  */
	    int fd = open (dbs[cnt].db_filename, O_RDWR);
	    if (fd != -1)
	      {
		struct stat64 st;
		void *mem;
		size_t total;
		struct database_pers_head head;
		ssize_t n = TEMP_FAILURE_RETRY (read (fd, &head,
						      sizeof (head)));
		if (n != sizeof (head) || fstat64 (fd, &st) != 0)
		  {
		  fail_db:
		    dbg_log (_("invalid persistent database file \"%s\": %s"),
			     dbs[cnt].db_filename, strerror (errno));
		    dbs[cnt].persistent = 0;
		  }
		else if (head.module == 0 && head.data_size == 0)
		  {
		    /* The file has been created, but the head has not been
		       initialized yet.  Remove the old file.  */
		    unlink (dbs[cnt].db_filename);
		  }
		else if (head.header_size != (int) sizeof (head))
		  {
		    dbg_log (_("invalid persistent database file \"%s\": %s"),
			     dbs[cnt].db_filename,
			     _("header size does not match"));
		    dbs[cnt].persistent = 0;
		  }
		else if ((total = (sizeof (head)
				   + roundup (head.module * sizeof (ref_t),
					      ALIGN)
				   + head.data_size))
			 > st.st_size)
		  {
		    dbg_log (_("invalid persistent database file \"%s\": %s"),
			     dbs[cnt].db_filename,
			     _("file size does not match"));
		    dbs[cnt].persistent = 0;
		  }
		else if ((mem = mmap (NULL, total, PROT_READ | PROT_WRITE,
				      MAP_SHARED, fd, 0)) == MAP_FAILED)
		  goto fail_db;
		else
		  {
		    /* Success.  We have the database.  */
		    dbs[cnt].head = mem;
		    dbs[cnt].memsize = total;
		    dbs[cnt].data = (char *)
		      &dbs[cnt].head->array[roundup (dbs[cnt].head->module,
						     ALIGN / sizeof (ref_t))];
		    dbs[cnt].mmap_used = true;

		    if (dbs[cnt].suggested_module > head.module)
		      dbg_log (_("suggested size of table for database %s larger than the persistent database's table"),
			       dbnames[cnt]);

		    dbs[cnt].wr_fd = fd;
		    fd = -1;
		    /* We also need a read-only descriptor.  */
		    if (dbs[cnt].shared)
		      {
			dbs[cnt].ro_fd = open (dbs[cnt].db_filename, O_RDONLY);
			if (dbs[cnt].ro_fd == -1)
			  dbg_log (_("\
cannot create read-only descriptor for \"%s\"; no mmap"),
				   dbs[cnt].db_filename);
		      }

		    // XXX Shall we test whether the descriptors actually
		    // XXX point to the same file?
		  }

		/* Close the file descriptors in case something went
		   wrong in which case the variable have not been
		   assigned -1.  */
		if (fd != -1)
		  close (fd);
	      }
	  }

	if (dbs[cnt].head == NULL)
	  {
	    /* No database loaded.  Allocate the data structure,
	       possibly on disk.  */
	    struct database_pers_head head;
	    size_t total = (sizeof (head)
			    + roundup (dbs[cnt].suggested_module
				       * sizeof (ref_t), ALIGN)
			    + (dbs[cnt].suggested_module
			       * DEFAULT_DATASIZE_PER_BUCKET));

	    /* Try to create the database.  If we do not need a
	       persistent database create a temporary file.  */
	    int fd;
	    int ro_fd = -1;
	    if (dbs[cnt].persistent)
	      {
		fd = open (dbs[cnt].db_filename,
			   O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
			   S_IRUSR | S_IWUSR);
		if (fd != -1 && dbs[cnt].shared)
		  ro_fd = open (dbs[cnt].db_filename, O_RDONLY);
	      }
	    else
	      {
		char fname[] = _PATH_NSCD_XYZ_DB_TMP;
		fd = mkstemp (fname);

		/* We do not need the file name anymore after we
		   opened another file descriptor in read-only mode.  */
		if (fd != -1)
		  {
		    if (dbs[cnt].shared)
		      ro_fd = open (fname, O_RDONLY);

		    unlink (fname);
		  }
	      }

	    if (fd == -1)
	      {
		if (errno == EEXIST)
		  {
		    dbg_log (_("database for %s corrupted or simultaneously used; remove %s manually if necessary and restart"),
			     dbnames[cnt], dbs[cnt].db_filename);
		    // XXX Correct way to terminate?
		    exit (1);
		  }

		if  (dbs[cnt].persistent)
		  dbg_log (_("cannot create %s; no persistent database used"),
			   dbs[cnt].db_filename);
		else
		  dbg_log (_("cannot create %s; no sharing possible"),
			   dbs[cnt].db_filename);

		dbs[cnt].persistent = 0;
		// XXX remember: no mmap
	      }
	    else
	      {
		/* Tell the user if we could not create the read-only
		   descriptor.  */
		if (ro_fd == -1 && dbs[cnt].shared)
		  dbg_log (_("\
cannot create read-only descriptor for \"%s\"; no mmap"),
			   dbs[cnt].db_filename);

		/* Before we create the header, initialiye the hash
		   table.  So that if we get interrupted if writing
		   the header we can recognize a partially initialized
		   database.  */
		size_t ps = sysconf (_SC_PAGESIZE);
		char tmpbuf[ps];
		assert (~ENDREF == 0);
		memset (tmpbuf, '\xff', ps);

		size_t remaining = dbs[cnt].suggested_module * sizeof (ref_t);
		off_t offset = sizeof (head);

		size_t towrite;
		if (offset % ps != 0)
		  {
		    towrite = MIN (remaining, ps - (offset % ps));
		    pwrite (fd, tmpbuf, towrite, offset);
		    offset += towrite;
		    remaining -= towrite;
		  }

		while (remaining > ps)
		  {
		    pwrite (fd, tmpbuf, ps, offset);
		    offset += ps;
		    remaining -= ps;
		  }

		if (remaining > 0)
		  pwrite (fd, tmpbuf, remaining, offset);

		/* Create the header of the file.  */
		struct database_pers_head head =
		  {
		    .version = DB_VERSION,
		    .header_size = sizeof (head),
		    .module = dbs[cnt].suggested_module,
		    .data_size = (dbs[cnt].suggested_module
				  * DEFAULT_DATASIZE_PER_BUCKET),
		    .first_free = 0
		  };
		void *mem;

		if ((TEMP_FAILURE_RETRY (write (fd, &head, sizeof (head)))
		     != sizeof (head))
		    || ftruncate (fd, total) != 0
		    || (mem = mmap (NULL, total, PROT_READ | PROT_WRITE,
				    MAP_SHARED, fd, 0)) == MAP_FAILED)
		  {
		    unlink (dbs[cnt].db_filename);
		    dbg_log (_("cannot write to database file %s: %s"),
			     dbs[cnt].db_filename, strerror (errno));
		    dbs[cnt].persistent = 0;
		  }
		else
		  {
		    /* Success.  */
		    dbs[cnt].head = mem;
		    dbs[cnt].data = (char *)
		      &dbs[cnt].head->array[roundup (dbs[cnt].head->module,
						     ALIGN / sizeof (ref_t))];
		    dbs[cnt].memsize = total;
		    dbs[cnt].mmap_used = true;

		    /* Remember the descriptors.  */
		    dbs[cnt].wr_fd = fd;
		    dbs[cnt].ro_fd = ro_fd;
		    fd = -1;
		    ro_fd = -1;
		  }

		if (fd != -1)
		  close (fd);
		if (ro_fd != -1)
		  close (ro_fd);
	      }
	  }

	if (paranoia
	    && ((dbs[cnt].wr_fd != -1
		 && fcntl (dbs[cnt].wr_fd, F_SETFD, FD_CLOEXEC) == -1)
		|| (dbs[cnt].ro_fd != -1
		    && fcntl (dbs[cnt].ro_fd, F_SETFD, FD_CLOEXEC) == -1)))
	  {
	    dbg_log (_("\
cannot set socket to close on exec: %s; disabling paranoia mode"),
		     strerror (errno));
	    paranoia = 0;
	  }

	if (dbs[cnt].head == NULL)
	  {
	    /* We do not use the persistent database.  Just
	       create an in-memory data structure.  */
	    assert (! dbs[cnt].persistent);

	    dbs[cnt].head = xmalloc (sizeof (struct database_pers_head)
				     + (dbs[cnt].suggested_module
					* sizeof (ref_t)));
	    memset (dbs[cnt].head, '\0', sizeof (dbs[cnt].head));
	    assert (~ENDREF == 0);
	    memset (dbs[cnt].head->array, '\xff',
		    dbs[cnt].suggested_module * sizeof (ref_t));
	    dbs[cnt].head->module = dbs[cnt].suggested_module;
	    dbs[cnt].head->data_size = (DEFAULT_DATASIZE_PER_BUCKET
					* dbs[cnt].head->module);
	    dbs[cnt].data = xmalloc (dbs[cnt].head->data_size);
	    dbs[cnt].head->first_free = 0;

	    dbs[cnt].shared = 0;
	    assert (dbs[cnt].ro_fd == -1);
	  }

	if (dbs[cnt].check_file)
	  {
	    /* We need the modification date of the file.  */
	    struct stat st;

	    if (stat (dbs[cnt].filename, &st) < 0)
	      {
		/* We cannot stat() the file, disable file checking.  */
		dbg_log (_("cannot stat() file `%s': %s"),
			 dbs[cnt].filename, strerror (errno));
		dbs[cnt].check_file = 0;
	      }
	    else
	      dbs[cnt].file_mtime = st.st_mtime;
	  }
      }

  /* Create the socket.  */
  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      dbg_log (_("cannot open socket: %s"), strerror (errno));
      exit (1);
    }
  /* Bind a name to the socket.  */
  struct sockaddr_un sock_addr;
  sock_addr.sun_family = AF_UNIX;
  strcpy (sock_addr.sun_path, _PATH_NSCDSOCKET);
  if (bind (sock, (struct sockaddr *) &sock_addr, sizeof (sock_addr)) < 0)
    {
      dbg_log ("%s: %s", _PATH_NSCDSOCKET, strerror (errno));
      exit (1);
    }

  /* We don't want to get stuck on accept.  */
  int fl = fcntl (sock, F_GETFL);
  if (fl == -1 || fcntl (sock, F_SETFL, fl | O_NONBLOCK) == -1)
    {
      dbg_log (_("cannot change socket to nonblocking mode: %s"),
	       strerror (errno));
      exit (1);
    }

  /* The descriptor needs to be closed on exec.  */
  if (paranoia && fcntl (sock, F_SETFD, FD_CLOEXEC) == -1)
    {
      dbg_log (_("cannot set socket to close on exec: %s"),
	       strerror (errno));
      exit (1);
    }

  /* Set permissions for the socket.  */
  chmod (_PATH_NSCDSOCKET, DEFFILEMODE);

  /* Set the socket up to accept connections.  */
  if (listen (sock, SOMAXCONN) < 0)
    {
      dbg_log (_("cannot enable socket to accept connections: %s"),
	       strerror (errno));
      exit (1);
    }

  /* Change to unprivileged uid/gid/groups if specifed in config file */
  if (server_user != NULL)
    finish_drop_privileges ();
}


/* Close the connections.  */
void
close_sockets (void)
{
  close (sock);
}


static void
invalidate_cache (char *key)
{
  dbtype number;

  if (strcmp (key, "passwd") == 0)
    number = pwddb;
  else if (strcmp (key, "group") == 0)
    number = grpdb;
  else if (__builtin_expect (strcmp (key, "hosts"), 0) == 0)
    {
      number = hstdb;

      /* Re-initialize the resolver.  resolv.conf might have changed.  */
      res_init ();
    }
  else
    return;

  if (dbs[number].enabled)
    prune_cache (&dbs[number], LONG_MAX);
}


#ifdef SCM_RIGHTS
static void
send_ro_fd (struct database_dyn *db, char *key, int fd)
{
  /* If we do not have an read-only file descriptor do nothing.  */
  if (db->ro_fd == -1)
    return;

  /* We need to send some data along with the descriptor.  */
  struct iovec iov[1];
  iov[0].iov_base = key;
  iov[0].iov_len = strlen (key) + 1;

  /* Prepare the control message to transfer the descriptor.  */
  union
  {
    struct cmsghdr hdr;
    char bytes[CMSG_SPACE (sizeof (int))];
  } buf;
  struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 1,
			.msg_control = buf.bytes,
			.msg_controllen = sizeof (buf) };
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);

  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (int));

  *(int *) CMSG_DATA (cmsg) = db->ro_fd;

  msg.msg_controllen = cmsg->cmsg_len;

  /* Send the control message.  We repeat when we are interrupted but
     everything else is ignored.  */
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
  (void) TEMP_FAILURE_RETRY (sendmsg (fd, &msg, MSG_NOSIGNAL));

  if (__builtin_expect (debug_level > 0, 0))
    dbg_log (_("provide access to FD %d, for %s"), db->ro_fd, key);
}
#endif	/* SCM_RIGHTS */


/* Handle new request.  */
static void
handle_request (int fd, request_header *req, void *key, uid_t uid)
{
  if (__builtin_expect (req->version, NSCD_VERSION) != NSCD_VERSION)
    {
      if (debug_level > 0)
	dbg_log (_("\
cannot handle old request version %d; current version is %d"),
		 req->version, NSCD_VERSION);
      return;
    }

  /* Make the SELinux check before we go on to the standard checks.  We
     need to verify that the request type is valid, since it has not
     yet been checked at this point.  */
  if (selinux_enabled
      && __builtin_expect (req->type, GETPWBYNAME) >= GETPWBYNAME
      && __builtin_expect (req->type, LASTREQ) < LASTREQ
      && nscd_request_avc_has_perm (fd, req->type) != 0)
    return;

  struct database_dyn *db = serv2db[req->type];

  // XXX Clean up so that each new command need not introduce a
  // XXX new conditional.
  if ((__builtin_expect (req->type, GETPWBYNAME) >= GETPWBYNAME
       && __builtin_expect (req->type, LASTDBREQ) <= LASTDBREQ)
      || req->type == GETAI || req->type == INITGROUPS)
    {
      if (__builtin_expect (debug_level, 0) > 0)
	{
	  if (req->type == GETHOSTBYADDR || req->type == GETHOSTBYADDRv6)
	    {
	      char buf[INET6_ADDRSTRLEN];

	      dbg_log ("\t%s (%s)", serv2str[req->type],
		       inet_ntop (req->type == GETHOSTBYADDR
				  ? AF_INET : AF_INET6,
				  key, buf, sizeof (buf)));
	    }
	  else
	    dbg_log ("\t%s (%s)", serv2str[req->type], (char *) key);
	}

      /* Is this service enabled?  */
      if (!db->enabled)
	{
	  /* No, sent the prepared record.  */
	  if (TEMP_FAILURE_RETRY (write (fd, db->disabled_iov->iov_base,
					 db->disabled_iov->iov_len))
	      != (ssize_t) db->disabled_iov->iov_len
	      && __builtin_expect (debug_level, 0) > 0)
	    {
	      /* We have problems sending the result.  */
	      char buf[256];
	      dbg_log (_("cannot write result: %s"),
		       strerror_r (errno, buf, sizeof (buf)));
	    }

	  return;
	}

      /* Be sure we can read the data.  */
      if (__builtin_expect (pthread_rwlock_tryrdlock (&db->lock) != 0, 0))
	{
	  ++db->head->rdlockdelayed;
	  pthread_rwlock_rdlock (&db->lock);
	}

      /* See whether we can handle it from the cache.  */
      struct datahead *cached;
      cached = (struct datahead *) cache_search (req->type, key, req->key_len,
						 db, uid);
      if (cached != NULL)
	{
	  /* Hurray it's in the cache.  */
	  if (writeall (fd, cached->data, cached->recsize)
	      != cached->recsize
	      && __builtin_expect (debug_level, 0) > 0)
	    {
	      /* We have problems sending the result.  */
	      char buf[256];
	      dbg_log (_("cannot write result: %s"),
		       strerror_r (errno, buf, sizeof (buf)));
	    }

	  pthread_rwlock_unlock (&db->lock);

	  return;
	}

      pthread_rwlock_unlock (&db->lock);
    }
  else if (__builtin_expect (debug_level, 0) > 0)
    {
      if (req->type == INVALIDATE)
	dbg_log ("\t%s (%s)", serv2str[req->type], (char *) key);
      else
	dbg_log ("\t%s", serv2str[req->type]);
    }

  /* Handle the request.  */
  switch (req->type)
    {
    case GETPWBYNAME:
      addpwbyname (db, fd, req, key, uid);
      break;

    case GETPWBYUID:
      addpwbyuid (db, fd, req, key, uid);
      break;

    case GETGRBYNAME:
      addgrbyname (db, fd, req, key, uid);
      break;

    case GETGRBYGID:
      addgrbygid (db, fd, req, key, uid);
      break;

    case GETHOSTBYNAME:
      addhstbyname (db, fd, req, key, uid);
      break;

    case GETHOSTBYNAMEv6:
      addhstbynamev6 (db, fd, req, key, uid);
      break;

    case GETHOSTBYADDR:
      addhstbyaddr (db, fd, req, key, uid);
      break;

    case GETHOSTBYADDRv6:
      addhstbyaddrv6 (db, fd, req, key, uid);
      break;

    case GETAI:
      addhstai (db, fd, req, key, uid);
      break;

    case INITGROUPS:
      addinitgroups (db, fd, req, key, uid);
      break;

    case GETSTAT:
    case SHUTDOWN:
    case INVALIDATE:
      if (! secure_in_use)
	{
	  /* Get the callers credentials.  */
#ifdef SO_PEERCRED
	  struct ucred caller;
	  socklen_t optlen = sizeof (caller);

	  if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &caller, &optlen) < 0)
	    {
	      char buf[256];

	      dbg_log (_("error getting callers id: %s"),
		       strerror_r (errno, buf, sizeof (buf)));
	      break;
	    }

	  uid = caller.uid;
#else
	  /* Some systems have no SO_PEERCRED implementation.  They don't
	     care about security so we don't as well.  */
	  uid = 0;
#endif
	}

      /* Accept shutdown, getstat and invalidate only from root.  For
	 the stat call also allow the user specified in the config file.  */
      if (req->type == GETSTAT)
	{
	  if (uid == 0 || uid == stat_uid)
	    send_stats (fd, dbs);
	}
      else if (uid == 0)
	{
	  if (req->type == INVALIDATE)
	    invalidate_cache (key);
	  else
	    termination_handler (0);
	}
      break;

    case GETFDPW:
    case GETFDGR:
    case GETFDHST:
#ifdef SCM_RIGHTS
      send_ro_fd (serv2db[req->type], key, fd);
#endif
      break;

    default:
      /* Ignore the command, it's nothing we know.  */
      break;
    }
}


/* Restart the process.  */
static void
restart (void)
{
  /* First determine the parameters.  We do not use the parameters
     passed to main() since in case nscd is started by running the
     dynamic linker this will not work.  Yes, this is not the usual
     case but nscd is part of glibc and we occasionally do this.  */
  size_t buflen = 1024;
  char *buf = alloca (buflen);
  size_t readlen = 0;
  int fd = open ("/proc/self/cmdline", O_RDONLY);
  if (fd == -1)
    {
      dbg_log (_("\
cannot open /proc/self/cmdline: %s; disabling paranoia mode"),
	       strerror (errno));

      paranoia = 0;
      return;
    }

  while (1)
    {
      ssize_t n = TEMP_FAILURE_RETRY (read (fd, buf + readlen,
					    buflen - readlen));
      if (n == -1)
	{
	  dbg_log (_("\
cannot open /proc/self/cmdline: %s; disabling paranoia mode"),
		   strerror (errno));

	  close (fd);
	  paranoia = 0;
	  return;
	}

      readlen += n;

      if (readlen < buflen)
	break;

      /* We might have to extend the buffer.  */
      size_t old_buflen = buflen;
      char *newp = extend_alloca (buf, buflen, 2 * buflen);
      buf = memmove (newp, buf, old_buflen);
    }

  close (fd);

  /* Parse the command line.  Worst case scenario: every two
     characters form one parameter (one character plus NUL).  */
  char **argv = alloca ((readlen / 2 + 1) * sizeof (argv[0]));
  int argc = 0;

  char *cp = buf;
  while (cp < buf + readlen)
    {
      argv[argc++] = cp;
      cp = (char *) rawmemchr (cp, '\0') + 1;
    }
  argv[argc] = NULL;

  /* Second, change back to the old user if we changed it.  */
  if (server_user != NULL)
    {
      if (setuid (old_uid) != 0)
	{
	  dbg_log (_("\
cannot change to old UID: %s; disabling paranoia mode"),
		   strerror (errno));

	  paranoia = 0;
	  return;
	}

      if (setgid (old_gid) != 0)
	{
	  dbg_log (_("\
cannot change to old GID: %s; disabling paranoia mode"),
		   strerror (errno));

	  setuid (server_uid);
	  paranoia = 0;
	  return;
	}
    }

  /* Next change back to the old working directory.  */
  if (chdir (oldcwd) == -1)
    {
      dbg_log (_("\
cannot change to old working directory: %s; disabling paranoia mode"),
	       strerror (errno));

      if (server_user != NULL)
	{
	  setuid (server_uid);
	  setgid (server_gid);
	}
      paranoia = 0;
      return;
    }

  /* Synchronize memory.  */
  for (int cnt = 0; cnt < lastdb; ++cnt)
    {
      /* Make sure nobody keeps using the database.  */
      dbs[cnt].head->timestamp = 0;

      if (dbs[cnt].persistent)
	// XXX async OK?
	msync (dbs[cnt].head, dbs[cnt].memsize, MS_ASYNC);
    }

  /* The preparations are done.  */
  execv ("/proc/self/exe", argv);

  /* If we come here, we will never be able to re-exec.  */
  dbg_log (_("re-exec failed: %s; disabling paranoia mode"),
	   strerror (errno));

  if (server_user != NULL)
    {
      setuid (server_uid);
      setgid (server_gid);
    }
  chdir ("/");
  paranoia = 0;
}


/* List of file descriptors.  */
struct fdlist
{
  int fd;
  struct fdlist *next;
};
/* Memory allocated for the list.  */
static struct fdlist *fdlist;
/* List of currently ready-to-read file descriptors.  */
static struct fdlist *readylist;

/* Conditional variable and mutex to signal availability of entries in
   READYLIST.  The condvar is initialized dynamically since we might
   use a different clock depending on availability.  */
static pthread_cond_t readylist_cond;
static pthread_mutex_t readylist_lock = PTHREAD_MUTEX_INITIALIZER;

/* The clock to use with the condvar.  */
static clockid_t timeout_clock = CLOCK_REALTIME;

/* Number of threads ready to handle the READYLIST.  */
static unsigned long int nready;


/* This is the main loop.  It is replicated in different threads but the
   `poll' call makes sure only one thread handles an incoming connection.  */
static void *
__attribute__ ((__noreturn__))
nscd_run (void *p)
{
  const long int my_number = (long int) p;
  const int run_prune = my_number < lastdb && dbs[my_number].enabled;
  struct timespec prune_ts;
  int to = 0;
  char buf[256];

  if (run_prune)
    {
      setup_thread (&dbs[my_number]);

      /* We are running.  */
      dbs[my_number].head->timestamp = time (NULL);

      if (clock_gettime (timeout_clock, &prune_ts) == -1)
	/* Should never happen.  */
	abort ();

      /* Compute timeout time.  */
      prune_ts.tv_sec += CACHE_PRUNE_INTERVAL;
    }

  /* Initial locking.  */
  pthread_mutex_lock (&readylist_lock);

  /* One more thread available.  */
  ++nready;

  while (1)
    {
      while (readylist == NULL)
	{
	  if (run_prune)
	    {
	      /* Wait, but not forever.  */
	      to = pthread_cond_timedwait (&readylist_cond, &readylist_lock,
					   &prune_ts);

	      /* If we were woken and there is no work to be done,
		 just start pruning.  */
	      if (readylist == NULL && to == ETIMEDOUT)
		{
		  --nready;
		  pthread_mutex_unlock (&readylist_lock);
		  goto only_prune;
		}
	    }
	  else
	    /* No need to timeout.  */
	    pthread_cond_wait (&readylist_cond, &readylist_lock);
	}

      struct fdlist *it = readylist->next;
      if (readylist->next == readylist)
	/* Just one entry on the list.  */
	readylist = NULL;
      else
	readylist->next = it->next;

      /* Extract the information and mark the record ready to be used
	 again.  */
      int fd = it->fd;
      it->next = NULL;

      /* One more thread available.  */
      --nready;

      /* We are done with the list.  */
      pthread_mutex_unlock (&readylist_lock);

      /* We do not want to block on a short read or so.  */
      int fl = fcntl (fd, F_GETFL);
      if (fl == -1 || fcntl (fd, F_SETFL, fl | O_NONBLOCK) == -1)
	goto close_and_out;

      /* Now read the request.  */
      request_header req;
      if (__builtin_expect (TEMP_FAILURE_RETRY (read (fd, &req, sizeof (req)))
			    != sizeof (req), 0))
	{
	  /* We failed to read data.  Note that this also might mean we
	     failed because we would have blocked.  */
	  if (debug_level > 0)
	    dbg_log (_("short read while reading request: %s"),
		     strerror_r (errno, buf, sizeof (buf)));
	  goto close_and_out;
	}

      /* Check whether this is a valid request type.  */
      if (req.type < GETPWBYNAME || req.type >= LASTREQ)
	goto close_and_out;

      /* Some systems have no SO_PEERCRED implementation.  They don't
	 care about security so we don't as well.  */
      uid_t uid = -1;
#ifdef SO_PEERCRED
      pid_t pid = 0;

      if (secure_in_use)
	{
	  struct ucred caller;
	  socklen_t optlen = sizeof (caller);

	  if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &caller, &optlen) < 0)
	    {
	      dbg_log (_("error getting callers id: %s"),
		       strerror_r (errno, buf, sizeof (buf)));
	      goto close_and_out;
	    }

	  if (req.type < GETPWBYNAME || req.type > LASTDBREQ
	      || serv2db[req.type]->secure)
	    uid = caller.uid;

	  pid = caller.pid;
	}
      else if (__builtin_expect (debug_level > 0, 0))
	{
	  struct ucred caller;
	  socklen_t optlen = sizeof (caller);

	  if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &caller, &optlen) == 0)
	    pid = caller.pid;
	}
#endif

      /* It should not be possible to crash the nscd with a silly
	 request (i.e., a terribly large key).  We limit the size to 1kb.  */
#define MAXKEYLEN 1024
      if (__builtin_expect (req.key_len, 1) < 0
	  || __builtin_expect (req.key_len, 1) > MAXKEYLEN)
	{
	  if (debug_level > 0)
	    dbg_log (_("key length in request too long: %d"), req.key_len);
	}
      else
	{
	  /* Get the key.  */
	  char keybuf[MAXKEYLEN];

	  if (__builtin_expect (TEMP_FAILURE_RETRY (read (fd, keybuf,
							  req.key_len))
				!= req.key_len, 0))
	    {
	      /* Again, this can also mean we would have blocked.  */
	      if (debug_level > 0)
		dbg_log (_("short read while reading request key: %s"),
			 strerror_r (errno, buf, sizeof (buf)));
	      goto close_and_out;
	    }

	  if (__builtin_expect (debug_level, 0) > 0)
	    {
#ifdef SO_PEERCRED
	      if (pid != 0)
		dbg_log (_("\
handle_request: request received (Version = %d) from PID %ld"),
			 req.version, (long int) pid);
	      else
#endif
		dbg_log (_("\
handle_request: request received (Version = %d)"), req.version);
	    }

	  /* Phew, we got all the data, now process it.  */
	  handle_request (fd, &req, keybuf, uid);
	}

    close_and_out:
      /* We are done.  */
      close (fd);

      /* Check whether we should be pruning the cache. */
      assert (run_prune || to == 0);
      if (to == ETIMEDOUT)
	{
	only_prune:
	  /* The pthread_cond_timedwait() call timed out.  It is time
		 to clean up the cache.  */
	  assert (my_number < lastdb);
	  prune_cache (&dbs[my_number], time (NULL));

	  if (clock_gettime (timeout_clock, &prune_ts) == -1)
	    /* Should never happen.  */
	    abort ();

	  /* Compute next timeout time.  */
	  prune_ts.tv_sec += CACHE_PRUNE_INTERVAL;

	  /* In case the list is emtpy we do not want to run the prune
	     code right away again.  */
	  to = 0;
	}

      /* Re-locking.  */
      pthread_mutex_lock (&readylist_lock);

      /* One more thread available.  */
      ++nready;
    }
}


static unsigned int nconns;

static void
fd_ready (int fd)
{
  pthread_mutex_lock (&readylist_lock);

  /* Find an empty entry in FDLIST.  */
  size_t inner;
  for (inner = 0; inner < nconns; ++inner)
    if (fdlist[inner].next == NULL)
      break;
  assert (inner < nconns);

  fdlist[inner].fd = fd;

  if (readylist == NULL)
    readylist = fdlist[inner].next = &fdlist[inner];
  else
    {
      fdlist[inner].next = readylist->next;
      readylist = readylist->next = &fdlist[inner];
    }

  bool do_signal = true;
  if (__builtin_expect (nready == 0, 0))
    {
      ++client_queued;
      do_signal = false;

      /* Try to start another thread to help out.  */
      pthread_t th;
      if (nthreads < max_nthreads
	  && pthread_create (&th, &attr, nscd_run,
			     (void *) (long int) nthreads) == 0)
	{
	  /* We got another thread.  */
	  ++nthreads;
	  /* The new thread might new a kick.  */
	  do_signal = true;
	}

    }

  pthread_mutex_unlock (&readylist_lock);

  /* Tell one of the worker threads there is work to do.  */
  if (do_signal)
    pthread_cond_signal (&readylist_cond);
}


/* Check whether restarting should happen.  */
static inline int
restart_p (time_t now)
{
  return (paranoia && readylist == NULL && nready == nthreads
	  && now >= restart_time);
}


/* Array for times a connection was accepted.  */
static time_t *starttime;


static void
__attribute__ ((__noreturn__))
main_loop_poll (void)
{
  struct pollfd *conns = (struct pollfd *) xmalloc (nconns
						    * sizeof (conns[0]));

  conns[0].fd = sock;
  conns[0].events = POLLRDNORM;
  size_t nused = 1;
  size_t firstfree = 1;

  while (1)
    {
      /* Wait for any event.  We wait at most a couple of seconds so
	 that we can check whether we should close any of the accepted
	 connections since we have not received a request.  */
#define MAX_ACCEPT_TIMEOUT 30
#define MIN_ACCEPT_TIMEOUT 5
#define MAIN_THREAD_TIMEOUT \
  (MAX_ACCEPT_TIMEOUT * 1000						      \
   - ((MAX_ACCEPT_TIMEOUT - MIN_ACCEPT_TIMEOUT) * 1000 * nused) / (2 * nconns))

      int n = poll (conns, nused, MAIN_THREAD_TIMEOUT);

      time_t now = time (NULL);

      /* If there is a descriptor ready for reading or there is a new
	 connection, process this now.  */
      if (n > 0)
	{
	  if (conns[0].revents != 0)
	    {
	      /* We have a new incoming connection.  Accept the connection.  */
	      int fd = TEMP_FAILURE_RETRY (accept (sock, NULL, NULL));

	      /* use the descriptor if we have not reached the limit.  */
	      if (fd >= 0 && firstfree < nconns)
		{
		  conns[firstfree].fd = fd;
		  conns[firstfree].events = POLLRDNORM;
		  starttime[firstfree] = now;
		  if (firstfree >= nused)
		    nused = firstfree + 1;

		  do
		    ++firstfree;
		  while (firstfree < nused && conns[firstfree].fd != -1);
		}

	      --n;
	    }

	  for (size_t cnt = 1; cnt < nused && n > 0; ++cnt)
	    if (conns[cnt].revents != 0)
	      {
		fd_ready (conns[cnt].fd);

		/* Clean up the CONNS array.  */
		conns[cnt].fd = -1;
		if (cnt < firstfree)
		  firstfree = cnt;
		if (cnt == nused - 1)
		  do
		    --nused;
		  while (conns[nused - 1].fd == -1);

		--n;
	      }
	}

      /* Now find entries which have timed out.  */
      assert (nused > 0);

      /* We make the timeout length depend on the number of file
	 descriptors currently used.  */
#define ACCEPT_TIMEOUT \
  (MAX_ACCEPT_TIMEOUT							      \
   - ((MAX_ACCEPT_TIMEOUT - MIN_ACCEPT_TIMEOUT) * nused) / nconns)
      time_t laststart = now - ACCEPT_TIMEOUT;

      for (size_t cnt = nused - 1; cnt > 0; --cnt)
	{
	  if (conns[cnt].fd != -1 && starttime[cnt] < laststart)
	    {
	      /* Remove the entry, it timed out.  */
	      (void) close (conns[cnt].fd);
	      conns[cnt].fd = -1;

	      if (cnt < firstfree)
		firstfree = cnt;
	      if (cnt == nused - 1)
		do
		  --nused;
		while (conns[nused - 1].fd == -1);
	    }
	}

      if (restart_p (now))
	restart ();
    }
}


#ifdef HAVE_EPOLL
static void
main_loop_epoll (int efd)
{
  struct epoll_event ev = { 0, };
  int nused = 1;
  size_t highest = 0;

  /* Add the socket.  */
  ev.events = EPOLLRDNORM;
  ev.data.fd = sock;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, sock, &ev) == -1)
    /* We cannot use epoll.  */
    return;

  while (1)
    {
      struct epoll_event revs[100];
# define nrevs (sizeof (revs) / sizeof (revs[0]))

      int n = epoll_wait (efd, revs, nrevs, MAIN_THREAD_TIMEOUT);

      time_t now = time (NULL);

      for (int cnt = 0; cnt < n; ++cnt)
	if (revs[cnt].data.fd == sock)
	  {
	    /* A new connection.  */
	    int fd = TEMP_FAILURE_RETRY (accept (sock, NULL, NULL));

	    if (fd >= 0)
	      {
		/* Try to add the  new descriptor.  */
		ev.data.fd = fd;
		if (fd >= nconns
		    || epoll_ctl (efd, EPOLL_CTL_ADD, fd, &ev) == -1)
		  /* The descriptor is too large or something went
		     wrong.  Close the descriptor.  */
		  close (fd);
		else
		  {
		    /* Remember when we accepted the connection.  */
		    starttime[fd] = now;

		    if (fd > highest)
		      highest = fd;

		    ++nused;
		  }
	      }
	  }
	else
	  {
	    /* Remove the descriptor from the epoll descriptor.  */
	    struct epoll_event ev = { 0, };
	    (void) epoll_ctl (efd, EPOLL_CTL_DEL, revs[cnt].data.fd, &ev);

	    /* Get a worked to handle the request.  */
	    fd_ready (revs[cnt].data.fd);

	    /* Reset the time.  */
	    starttime[revs[cnt].data.fd] = 0;
	    if (revs[cnt].data.fd == highest)
	      do
		--highest;
	      while (highest > 0 && starttime[highest] == 0);

	    --nused;
	  }

      /*  Now look for descriptors for accepted connections which have
	  no reply in too long of a time.  */
      time_t laststart = now - ACCEPT_TIMEOUT;
      for (int cnt = highest; cnt > STDERR_FILENO; --cnt)
	if (cnt != sock && starttime[cnt] != 0 && starttime[cnt] < laststart)
	  {
	    /* We are waiting for this one for too long.  Close it.  */
	    struct epoll_event ev = {0, };
	    (void) epoll_ctl (efd, EPOLL_CTL_DEL, cnt, &ev);

	    (void) close (cnt);

	    starttime[cnt] = 0;
	    if (cnt == highest)
	      --highest;
	  }
	else if (cnt != sock && starttime[cnt] == 0 && cnt == highest)
	  --highest;

      if (restart_p (now))
	restart ();
    }
}
#endif


/* Start all the threads we want.  The initial process is thread no. 1.  */
void
start_threads (void)
{
  /* Initialize the conditional variable we will use.  The only
     non-standard attribute we might use is the clock selection.  */
  pthread_condattr_t condattr;
  pthread_condattr_init (&condattr);

#if defined _POSIX_CLOCK_SELECTION && _POSIX_CLOCK_SELECTION >= 0 \
    && defined _POSIX_MONOTONIC_CLOCK && _POSIX_MONOTONIC_CLOCK >= 0
  /* Determine whether the monotonous clock is available.  */
  struct timespec dummy;
# if _POSIX_MONOTONIC_CLOCK == 0
  if (sysconf (_SC_MONOTONIC_CLOCK) > 0)
# endif
# if _POSIX_CLOCK_SELECTION == 0
    if (sysconf (_SC_CLOCK_SELECTION) > 0)
# endif
      if (clock_getres (CLOCK_MONOTONIC, &dummy) == 0
	  && pthread_condattr_setclock (&condattr, CLOCK_MONOTONIC) == 0)
	timeout_clock = CLOCK_MONOTONIC;
#endif

  pthread_cond_init (&readylist_cond, &condattr);
  pthread_condattr_destroy (&condattr);


  /* Create the attribute for the threads.  They are all created
     detached.  */
  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
  /* Use 1MB stacks, twice as much for 64-bit architectures.  */
  pthread_attr_setstacksize (&attr, 1024 * 1024 * (sizeof (void *) / 4));

  /* We allow less than LASTDB threads only for debugging.  */
  if (debug_level == 0)
    nthreads = MAX (nthreads, lastdb);

  int nfailed = 0;
  for (long int i = 0; i < nthreads; ++i)
    {
      pthread_t th;
      if (pthread_create (&th, &attr, nscd_run, (void *) (i - nfailed)) != 0)
	++nfailed;
    }
  if (nthreads - nfailed < lastdb)
    {
      /* We could not start enough threads.  */
      dbg_log (_("could only start %d threads; terminating"),
	       nthreads - nfailed);
      exit (1);
    }

  /* Determine how much room for descriptors we should initially
     allocate.  This might need to change later if we cap the number
     with MAXCONN.  */
  const long int nfds = sysconf (_SC_OPEN_MAX);
#define MINCONN 32
#define MAXCONN 16384
  if (nfds == -1 || nfds > MAXCONN)
    nconns = MAXCONN;
  else if (nfds < MINCONN)
    nconns = MINCONN;
  else
    nconns = nfds;

  /* We need memory to pass descriptors on to the worker threads.  */
  fdlist = (struct fdlist *) xcalloc (nconns, sizeof (fdlist[0]));
  /* Array to keep track when connection was accepted.  */
  starttime = (time_t *) xcalloc (nconns, sizeof (starttime[0]));

  /* In the main thread we execute the loop which handles incoming
     connections.  */
#ifdef HAVE_EPOLL
  int efd = epoll_create (100);
  if (efd != -1)
    {
      main_loop_epoll (efd);
      close (efd);
    }
#endif

  main_loop_poll ();
}


/* Look up the uid, gid, and supplementary groups to run nscd as. When
   this function is called, we are not listening on the nscd socket yet so
   we can just use the ordinary lookup functions without causing a lockup  */
static void
begin_drop_privileges (void)
{
  struct passwd *pwd = getpwnam (server_user);

  if (pwd == NULL)
    {
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      error (EXIT_FAILURE, 0, _("Failed to run nscd as user '%s'"),
	     server_user);
    }

  server_uid = pwd->pw_uid;
  server_gid = pwd->pw_gid;

  /* Save the old UID/GID if we have to change back.  */
  if (paranoia)
    {
      old_uid = getuid ();
      old_gid = getgid ();
    }

  if (getgrouplist (server_user, server_gid, NULL, &server_ngroups) == 0)
    {
      /* This really must never happen.  */
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      error (EXIT_FAILURE, errno, _("initial getgrouplist failed"));
    }

  server_groups = (gid_t *) xmalloc (server_ngroups * sizeof (gid_t));

  if (getgrouplist (server_user, server_gid, server_groups, &server_ngroups)
      == -1)
    {
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      error (EXIT_FAILURE, errno, _("getgrouplist failed"));
    }
}


/* Call setgroups(), setgid(), and setuid() to drop root privileges and
   run nscd as the user specified in the configuration file.  */
static void
finish_drop_privileges (void)
{
  if (setgroups (server_ngroups, server_groups) == -1)
    {
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      error (EXIT_FAILURE, errno, _("setgroups failed"));
    }

  if (setgid (server_gid) == -1)
    {
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      perror ("setgid");
      exit (1);
    }

  if (setuid (server_uid) == -1)
    {
      dbg_log (_("Failed to run nscd as user '%s'"), server_user);
      perror ("setuid");
      exit (1);
    }
}
