import os
import sys
# Copyright (c) 2014, curesec GmbH
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of 
# conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list 
# of conditions and the following disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used 
# to endorse or promote products derived from this software without specific prior written 
# permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS 
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import threading
import signal

def _cleanup(signum, frame):
    """
    make some clean up to remove unneeded files (e.g. pid file)

    input:
        signum  signal number ended with
        frame   current stack fram (None or a frame object)

    """
    # path to pid file. The file will be removed on clean up and is set on
    # initialising the signal handler
    try:
        pid_fn = _cleanup.pid_fn
    except AttributeError:
        # _cleanup.pid_fn is not initialised so terminate
        return

    if pid_fn:
        print("removing pid %s" % pid_fn)
        os.remove(pid_fn)

def daemonise (name="", stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    """"
    This forks the current process into a daemon. The stdin, stdout, and
    stderr arguments are file names that will be opened and be used to replace
    the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null. Note that stderr is
    opened unbuffered, so if it shares a file with stdout then interleaved
    output may not appear in the order that you expect.

    input:
        name    name of the daemon to start, relevant e.g. for creating pid file
        stdin   forward stdin to
        stdout  forward stdout to
        stderr  forward stderr to

    output:
        mpid    daemon's pid

    """
    print("[%s] daemonising.." % (threading.currentThread().getName()))

    # fork() so the parent can exit, this returns control to the command line
    # or shell invoking your program. This step is required so that the new
    # process is guaranteed not to be a process group leader. The next step,
    # setsid(), fails if you're a process group leader.
    try:
        pid = os.fork()

        # pid > 0, pid of child process
        if pid > 0:
            sys.exit(0)   # Exit first parent.

    except OSError, e:
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # chdir("/") to ensure that our process doesn't keep any directory in use.
    os.chdir("/")

    # umask(0) so that we have complete control over the permissions of anything
    # we write. We don't know what umask we may have inherited.
    os.umask(0)

    # setsid() to become a process group and session group leader. Since a
    # controlling terminal is associated with a session, and this new session
    # has not yet acquired a controlling terminal our process now has no
    # controlling terminal, which is a Good Thing for daemons.
    os.setsid()

    # fork() again so the parent, (the session group leader), can exit. This
    # means that we, as a non-session group leader, can never regain a
    # controlling terminal.
    try:
        pid = os.fork()

        # pid > 0, pid of child process
        if pid > 0:
            sys.exit(0)   # Exit second parent.

    except OSError, e:
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    # Now I am a daemon!
    # write pid file
    mpid = os.getpid()
    if name:
        path = "/var/run/%s.pid" % name
        print("creating %s" % path)
        with open(path,"w") as f:
            f.write(str(mpid))


    # Redirect standard file descriptors.
    print("redirecting stdin=%s, "
          "stdout=%s, "
          "stderr=%s" % (stdin, stdout, stderr))
    si = open(stdin, 'a')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # if the daemon terminates, clean up (remove pid file, etc pp)
    _cleanup.pid_fn = path
    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    print("returning pid:%d" % mpid)
    return mpid

def main ():

    # This is an example main function run by the daemon.
    # This prints a count and timestamp once per second.

    import time
    sys.stdout.write ('Daemon started with pid %d\n' % os.getpid() )
    sys.stdout.write ('Daemon stdout output\n')
    sys.stderr.write ('Daemon stderr output\n')
    c = 0
    while 1:
        sys.stdout.write ('%d: %s\n' % (c, time.ctime(time.time())) )
        sys.stdout.flush()
        c = c + 1
        time.sleep(1)

if __name__ == "__main__":
    daemonise('/dev/null','/tmp/daemon.log','/tmp/daemon.log')
    main()
