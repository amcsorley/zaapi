import os, errno

class mkDir:
    def __init__(self, path):
        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else: raise

class decryptSSL:
    def __init__(self, password, in_filename, out_filename):

        from hashlib import md5
        from Crypto.Cipher import AES
        
        def derive_key_and_iv(password, salt, key_length, iv_length):
             d = d_i = ''
             while len(d) < key_length + iv_length:
                 d_i = md5(d_i + password + salt).digest()
                 d += d_i
             return d[:key_length], d[key_length:key_length+iv_length]
        
        def decrypt(in_file, out_file, password, key_length=32):
             bs = AES.block_size
             salt = in_file.read(bs)[len('Salted__'):]
             key, iv = derive_key_and_iv(password, salt, key_length, bs)
             cipher = AES.new(key, AES.MODE_CBC, iv)
             next_chunk = ''
             finished = False
             while not finished:
                 chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                 if len(next_chunk) == 0:
                     chunk = chunk.rstrip(chunk[-1])
                     finished = True
                 out_file.write(chunk)

        in_file = open(in_filename, 'rb')
        out_file = open(out_filename, 'wb')
        decrypt(in_file, out_file, password)


class verifyKey:
    def __init__(self, key, keyfile):
        import hashlib
        key_hash = open(keyfile).readline().split()[0] 
        hash_of_key = hashlib.sha256(key).hexdigest()
        if key_hash == hash_of_key:
            self.key_check = True
        else:
            self.key_check = False

    def isgood(self):
        return self.key_check

class logCmd:
    def __init__(self, cmd, outfile):

        import subprocess
        import threading
        import logging
        import logging.handlers

        def get_log_handlers():
            log.setLevel(logging.DEBUG)
            syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
            log.addHandler(syslog_handler)
            file_handler = logging.handlers.RotatingFileHandler(outfile, maxBytes=512000, backupCount=20)
            formatR = logging.Formatter('%(asctime)s: %(message)s')
            file_handler.setFormatter(formatR)
            log.addHandler(file_handler)
            return syslog_handler, file_handler

        def log_thread(pipe, logger, cmd):
    
            def log_output(pipe, logger, cmd):
                syslog_handler, file_handler = get_log_handlers()
                logger('running ' + str(''.join(cmd)))
                for line in iter(pipe.readline, b''):
                    logger(line.rstrip('\n'))
                syslog_handler.close()
                file_handler.close()
                log.removeHandler(syslog_handler)
                log.removeHandler(file_handler)

            t = threading.Thread(target=log_output, args=(pipe, logger, cmd))
            t.daemon = True
            t.start()

        p = subprocess.Popen(
                cmd, shell=False,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, close_fds='posix')

        outdir = os.path.dirname(outfile)
        mkDir(outdir)

        #self.pid = p.pid
        #self.outfile = outdir + '/out.' + str(self.pid) + '.log'

        log = logging.getLogger(__name__)
        log_thread(p.stdout,log.info,cmd)
        #log_thread(p.stderr,log.warn)

    def get_outfile(self):
        return self.outfile


class tailFile:
    """a tail-like thing to put the last num_lines of filename into a list"""
    def __init__(self, filename, num_lines):

        import os
        from itertools import islice

        def reversed_lines(fh):
            """Generate the lines of file in reverse order."""
            part = ''
            for block in reversed_blocks(fh):
                for c in reversed(block):
                    if c == '\n' and part:
                        yield part[::-1]
                        part = ''
                    part += c
            if part: yield part[::-1]

        def reversed_blocks(fh, blocksize=4096):
            """Generate blocks of file's contents in reverse order."""
            fh.seek(0, os.SEEK_END)
            here = fh.tell()
            while 0 < here:
                delta = min(blocksize, here)
                here -= delta
                fh.seek(here, os.SEEK_SET)
                yield fh.read(delta)

        self.list = []
        if os.path.isfile(filename):
            fh = open(filename, 'r')
            for line in islice(reversed_lines(fh), num_lines):
                self.list.append(line.rstrip('\n'))
            #self.list.reverse()

    def get_tail(self):
        return self.list


class forkIt:
    def __init__(self, it, pidfile):
        import sys, os 

        try: 
            pid = os.fork() 
            if pid > 0:
                sys.exit(0) 
        except OSError, e: 
            print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror) 
            sys.exit(1)

        os.chdir("/") 
        os.setsid() 
        os.umask(0) 

        try: 
            pid = os.fork() 
            if pid > 0:
                #print "Daemon PID %d" % pid 
                if pidfile:
                    pf = open(pidfile, 'w')
                    pf.write(str(pid) + '\n')
                sys.exit(0) 
        except OSError, e: 
            print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
            sys.exit(1) 

        self.outfile = it()

    def get_outfile(self):
        return self.outfile

