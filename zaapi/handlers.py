#!/usr/bin/python

from zaapi_util import mkDir, logCmd, forkIt, tailFile, verifyKey, decryptSSL
from tornado.web import RequestHandler, asynchronous
from tornado import gen
from tornado.ioloop import IOLoop
import tornado.httpclient
import subprocess as sp
import os, json, re, glob, telnetlib, urllib2, binascii
import tarfile, magic
import ConfigParser

try:
    import chef
except:
    pass

config = ConfigParser.ConfigParser()
config.read('/etc/zaapi/zaapi.conf')
logdir = config.get('defaults', 'logdir')
port = config.get('defaults', 'port')
public_port = config.get('defaults', 'public_port')
apikeyfile = config.get('defaults', 'apikeyfile')

def isValidHostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def isValidShortHostname(hostname):
    if len(hostname) > 63:
        return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return allowed.match(hostname)

class ExampleAsync(RequestHandler):
    url = "https://localhost:" + port + "/help"
    client = tornado.httpclient.AsyncHTTPClient()
    @asynchronous
    @gen.engine
    def get(self):
        response = yield gen.Task(self.client.fetch, self.url, validate_cert=False)
        self.set_header("Content-Type", "application/json")
        self.finish(response.body)

class Help(RequestHandler):
    def get(self):
        """Print available functions"""
        result = { 'Help' : 'Print available functions' }
        self.write(result)
        #for rule in app.url_map.iter_rules():
        #    if rule.endpoint != 'static':
        #        func_list[rule.rule] = app.view_functions[rule.endpoint].__doc__
        #return jsonify(func_list)

class PubHelp(RequestHandler):
    def get(self):
       """Print available public functions"""
       result = { 'Help' : 'Print available public functions' }
       self.write(result)

class ZenossCollectorInit(RequestHandler):
    def get(self, collector_key):
        """Get a collector initiation file for <collector_key>"""
        result = {}
        stack_collector_num, apikey = collector_key.split('-')
        if verifyKey(apikey, apikeyfile).isgood():
            stack_collector_name = stack_collector_num.decode('hex')
            stack_name = stack_collector_name.split('-')[0]
            collector_num = stack_collector_name.split('-')[1]
            collector_name = stack_name + '-collector-' + collector_num
            enc_init_file_path = '/mnt/*'+ stack_name + '*/' + collector_name + '-init.tgz.aes256'
            enc_init_file = glob.glob(enc_init_file_path)
            try:
                fh = open(enc_init_file[0])
                result = fh.read()
            except:
                pass
        self.write(result)

def zenoss_status():
    cmd = '/bin/su -l zenoss -c "zenoss status"'
    child = sp.Popen(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    output = {}
    while True:
        line = child.stdout.readline().strip()
        if not line:
            break
        parts = re.split('\W+', line)
        daemon, status, pid = '', '', ''
        daemon, status = parts[1], parts[2] + ' ' + parts[3]
        if 5 < len(parts):
            pid = parts[5]
        output.update({ daemon : { "status" : status, "pid" : pid} })
    child.communicate()
    exit_code = child.returncode
    return output, exit_code

def test_zenoss_status():
    """Run shell command to get zenoss status and pass or fail based on the exit status""" 
    test_name = 'zenoss_status'
    test_result = 'fail'
    output, exit_code = zenoss_status()
    if exit_code == 0:
        test_result = 'pass'
    result = {test_name : test_result}
    return result

class ZenossStatusTest(RequestHandler):
    def get(self):
        """Run shell command to get zenoss status and pass or fail based on the exit status""" 
        result = test_zenoss_status()
        self.write(result)

class ZenossStatus(RequestHandler):
    def get(self):
        """Run shell command to get zenoss status"""
        result, exit_code = zenoss_status()
        self.write(result)

def test_rabbitmq_status():
    test_name = 'rabbitmq_status'
    test_result = 'fail'
    cmd = '/bin/su -l rabbitmq -c "rabbitmqctl -q status"'
    child = sp.Popen(cmd, shell=True, stdout=sp.PIPE)
    child.communicate()
    if child.returncode == 0:
        test_result = 'pass'
    result = {test_name : test_result}
    return result

class RabbitmqStatus(RequestHandler):
    def get(self):
        """Run shell command to get rabbitmq status"""
        cmd = '/bin/su -l rabbitmq -c "rabbitmqctl -q status"'
        # had to do a crapload of replaces to make the output of
        # rabbitmqctl look like json, if you're reading this and
        # know a better way to do this, please update it
        child = sp.Popen(cmd, shell=True, stdout=sp.PIPE)
        js = ( child.stdout.read().replace('\n', '')
             .strip('[').rstrip(']')
             .replace('","', ' ')
             .replace('"', '')
             .replace('     ', '') )
        lines = re.split(', ', js)
        for i, p in enumerate(lines):
            if p.startswith('{'):
                lines[i] = ( p.replace('{', '"', 1)
                           .replace('}]}', '"}], ', 1)
                           .replace('},{', '", "', 1)
                           .replace(',{', '": {"', 1)
                           .replace(',[{', '": [{"', 1)
                           .replace('}}', '"}, ', 1)
                           .replace(',', '": "') )
        for i, p in enumerate(lines):
            if p.endswith('}'):
                lines[i] = p.replace('}', '", ', 1)
        line = ( ''.join(lines).strip(', ')
               .replace('}]": " "', '}], "')
               .replace('}": " "', '}, "')
               .replace('"": " "', '", "')
               .replace('}": {"', '", "')
               .replace('}": "{', '", "')
               .replace('\\n', '') )
        if line:
            result = '{ ' + line + ' }'
        else:
            result = '{}'
        self.write(result)

class RabbitmqStatusTest(RequestHandler):
    def get(self):
        """Run shell command to get rabbitmq status and pass or fail based on the exit status""" 
        self.write(test_rabbitmq_status())

def memcached_status():
    host, port = '127.0.0.1', '11211'
    stat_regex = re.compile(ur"STAT (.*) (.*)\r")
    try:
        result = {}
        client = telnetlib.Telnet(host, port)
        client.write("stats \n")
        result = dict(stat_regex.findall(client.read_until('END')))
    except:
        pass
    return result

def test_memcached_status():
    test_name = 'memcached_status'
    test_result = 'fail'
    try:
        status = memcached_status()
        if status['accepting_conns'] == '1':
            test_result = 'pass'
    except:
        pass
    result = {test_name : test_result}
    return result

class MemcachedStatus(RequestHandler):
    def get(self):
        """Get STATS from the memcached telnet interface"""
        self.write(memcached_status())

class MemcachedStatusTest(RequestHandler):
    def get(self):
        """Get STATS from the memcached telnet interface and pass or fail based on whether it is accepting connections"""
        self.write(test_memcached_status())

def openvpn_status():
    host, port = '127.0.0.1', '1234'
    try:
        result = {}
        client = telnetlib.Telnet(host, port)
        client.write("state\n")
        response = re.findall("(.*),(.*),(.*),(.*),(.*)\r", client.read_until('END'))
        keys = ['unix_time', 'state_name', 'connection_status', 'local_ip', 'remote_server']
        result = [ dict(zip(keys,row)) for row in response ][0]
    except:
        pass
    return result

def test_openvpn_status():
    test_name = 'openvpn_status'
    test_result = 'fail'
    try:
        status = openvpn_status()
        state_name = status['state_name']
        connection_status = status['connection_status']
        local_ip = status['local_ip']
        if state_name == 'CONNECTED' and connection_status == 'SUCCESS' and local_ip == '10.40.88.1':
            test_result = 'pass'
    except:
        pass
    result = {test_name : test_result}
    return result

class OpenvpnStatus(RequestHandler):
    def get(self):
        """Get state from the openvpn telnet interface"""
        result = openvpn_status()
        self.write(result)

class OpenvpnStatusTest(RequestHandler):
    def get(self):
        """Get state from the openvpn telnet interface and pass or fail based on connection status"""
        result = test_openvpn_status()
        self.write(result)

def zenoss_copyright(hostname):
    url = 'https://' + hostname
    exp = '(Copyright)\D+(\d+-\d+).*(Zenoss.*Inc).*(Version)\D+(\d+\.\d+\.\d+)'
    p = re.compile(exp)
    result = {}
    try:
        oneline = ''.join(urllib2.urlopen(url).read()).replace('\n', ' ')
        match = p.search(oneline)
        if match:
            result[match.group(1)] = ' '.join(match.group(2,3))
            result[match.group(4)] = match.group(5)
    except:
        pass
    return result

def test_zenoss_copyright(hostname):
    test_name = 'zenoss_copyright'
    test_result = 'fail'
    try:
        status = zenoss_copyright(hostname)
        exp = 'Zenoss.*Inc'
        p = re.compile(exp)
        if p.search(status['Copyright']):
            test_result = 'pass'
    except:
        pass
    result = {test_name : test_result}
    return result

class ZenossCopyright(RequestHandler):
    def get(self, hostname):
        """Get get copyright and version from Zenoss login screen for <hostname>"""
        if isValidHostname(hostname):
            result = zenoss_copyright(hostname)
        else:
            result = {'error':'invalid hostname'}
        self.write(result)

class ZenossCopyrightTest(RequestHandler):
    def get(self, hostname):
        """Test for copyright on Zenoss login screen for <hostname>"""
        if isValidHostname(hostname):
            result = test_zenoss_copyright(hostname)
        else:
            result = {'error':'invalid hostname'}
        self.write(result)

class ZenossCollectorAdd(RequestHandler):
    def get(self, collector_name):
        """Run dc-admin add-collector for <collector_name>"""
        sshcmd = 'ssh -Tn -o StrictHostKeyChecking=no root@' + collector_name
        sshcmdsuzenoss = ['/bin/su', '-l', 'zenoss', '-c', sshcmd]
        runsshcmd = sp.Popen(sshcmdsuzenoss, shell=False, stdout=sp.PIPE)
        if not isValidShortHostname(collector_name):
            result = {'error':'invalid hostname'}
        elif runsshcmd.communicate() and runsshcmd.returncode == 0:
            outfile = logdir + 'add_' + collector_name + '.out'
            dcadmincmd = 'dc-admin add-collector --collector-host=' + collector_name + ' --install-user=root --install-password= ' + collector_name + ' localhost'
            cmd = ['/bin/su', '-l', 'zenoss', '-c', dcadmincmd]
            logCmd(cmd, outfile)
            result = {'output_file': outfile}
        else:
            result = {'error': 'cannot ssh to collector'}
        self.write(result)

class ZenossCollectorAddStatus(RequestHandler):
    def get(self, collector_name):
        """tail the output file from add_collector for <collector_name>"""
        callback = self.get_argument('callback', default=[])
        numlines = int(self.get_argument('numlines', default=1))
        outfile = logdir + 'add_' + collector_name + '.out'
        lines = tailFile(outfile, numlines).get_tail()
        #result = {outfile : lines}
        result = {'result' : lines}
        if callback == 'getData':
            d = json.dumps(result)
            self.set_header('Content-Type', 'application/javascript')
            self.write('getData(' + d + ');')
        else:
            self.write(result)

class ZenossCollectorPodAdd(RequestHandler):
    @asynchronous
    @gen.engine
    def get(self, host):
        """Add <host> to device class in POD for monitoring"""
        deviceclass = self.get_argument('deviceclass', default='/Server/SSH/Linux/Collector')
        #productionState wants an int Prod=1000,PreProd=500,Maint=300,Test=0,Decom=-1
        prodstate = str(self.get_argument('prodstate', default="500"))
        chefapi = chef.autoconfigure()
        master = chef.Node(chefapi.client)
        vpcid = master['vpc_id']
        privip = master['private_ips'][0]
        stackname = master['cluster']['name']
        collectors = master['zenoss']['collector-passwords']
        zaasdomain = master['zaas']['domain']

        for c in collectors:
            if c['collector'] == host:
                #devicename = c['ip']
                devicename = host + '.' + stackname + '.internal.' + zaasdomain

        pod = chef.Search('node', 'hostname:POD* AND vpc_id:' + vpcid)
        podip = pod[0]['automatic']['ipaddress']
        password = pod[0]['normal']['zenoss']['password']
        user = 'admin'
        url = 'https://' + podip + '/zport/dmd/device_router'
        data = '{"action":"DeviceRouter","method":"addDevice","data":[{"deviceName":"'+devicename+'","deviceClass":"'+deviceclass+'","collector":"localhost","title":"'+host+'","productionState":"'+prodstate+'"}],"tid":1}'
        userpass = user + ":" + password
        auth = "Basic " + userpass.encode("base64").rstrip()
        headers = {"Authorization": auth,
                   "Content-Type": "application/json; charset=utf-8"}

        request = tornado.httpclient.HTTPRequest(
            url=url,
            method='POST',
            body=data,
            headers=headers,
            validate_cert=False)

        client = tornado.httpclient.AsyncHTTPClient()
        response = yield tornado.gen.Task(client.fetch, request)
        self.finish(response.body)


def zenoss_collector_key_setup(collector_key):
    random_string = binascii.b2a_hex(os.urandom(3))
    tmpdir = '/tmp/collectar/' + random_string + '/'
    mkDir(tmpdir)
    encfile = tmpdir + 'test.enc'
    tgzfile = tmpdir + 'test.tgz'
    stack_collector_num, apikey, decryptkey = collector_key.split('-')
    try:
        stack_collector_name = stack_collector_num.decode('hex')
        stack_name = stack_collector_name.split('-')[0]
        collector_num = stack_collector_name.split('-')[1]
        colname = stack_name + '-collector-' + collector_num
    except:
        colname = 'NO_COLLECTOR_NAME'
        pass
    password = str(decryptkey)
    getkey = stack_collector_num + '-' + apikey
    url = 'https://localhost:' + public_port + '/zenoss/collector/init/' + getkey
    return url, password, encfile, tgzfile, colname

def zenoss_collector_key_open(response, password, encfile, tgzfile):
    result = {}
    result['files'] = {}
    result['errors'] = {}
    output = open(encfile,'wb')
    output.write(response)
    output.close()
    m = magic.open(magic.MAGIC_MIME)
    m.load()
    filetype = m.file(encfile)
    if re.search(r'.*octet-stream.*', filetype):
        decryptSSL(password, encfile, tgzfile)
        if tarfile.is_tarfile(tgzfile):
            tar = tarfile.open(tgzfile)
            for tarinfo in tar:
                result['files'][tarinfo.name] = str(tarinfo.size)
        os.remove(tgzfile)
        os.remove(encfile)
        os.rmdir(os.path.dirname(encfile))
    else:
        result['errors']['encrypted_file_type'] = filetype
    return result

def zenoss_collector_key_test(colname, contents):
    test_name = 'zenoss_collector_key'
    test_result = 'fail'
    try:
        if contents['files']['collector-init/vpn/' + colname + '.conf'] > '0':
            test_result = 'pass'
    except:
        pass
    result = { test_name : test_result }
    return result

class ZenossCollectorKeyFiles(RequestHandler):
    """Confirm the given collector key works"""
    client = tornado.httpclient.AsyncHTTPClient()
    @asynchronous
    @gen.engine
    def get(self, collector_key):
        url, password, encfile, tgzfile, colname = zenoss_collector_key_setup(collector_key)
        response = yield gen.Task(self.client.fetch, url, validate_cert=False)
        result = zenoss_collector_key_open(response.body, password, encfile, tgzfile)
        self.write(result)
        self.finish()

class ZenossCollectorKeyTest(RequestHandler):
    """Confirm the given collector key works"""
    client = tornado.httpclient.AsyncHTTPClient()
    @asynchronous
    @gen.engine
    def get(self, collector_key):
        url, password, encfile, tgzfile, colname = zenoss_collector_key_setup(collector_key)
        response = yield gen.Task(self.client.fetch, url, validate_cert=False)
        contents = zenoss_collector_key_open(response.body, password, encfile, tgzfile)
        result = zenoss_collector_key_test(colname, contents)
        self.write(result)
        self.finish()

def aws_s3_mount_test():
    test_name = 'aws_s3_mount'
    test_result = 'fail'
    random_string = binascii.b2a_hex(os.urandom(5))
    testfilename = test_name + '_test-' + random_string
    proc_mounts = open('/proc/mounts')
    s3fs_regex = "^s3fs\s+/mnt/\w+-s3bucket-\w+\s+fuse\.s3fs\s+"
    
    for line in proc_mounts:
        if re.match(s3fs_regex, line):
            mountpoint = line.split()[1]
            testfile = mountpoint + '/' + testfilename
            try:
                writefh = open(testfile, 'w')
                writefh.write(random_string)
                writefh.close()
            except:
                pass
    
            try:
                readfh = open(testfile, 'r')
                for line in readfh:
                    if re.match('^'+random_string+'$', line):
                        readfh.close()
                        os.remove(testfile)
                        test_result = 'pass'
                        break
            except:
                pass
    
    proc_mounts.close()
    result = { test_name : test_result }
    return result

class AwsS3MountTest(RequestHandler):
    """Confirm the Amazon S3 mount exists and is writable"""
    def get(self):
        result = aws_s3_mount_test()
        self.write(result)

class AllTest(RequestHandler):
    def get(self):
        """Run all tests"""
        result = ( dict(test_memcached_status().items()
               + test_rabbitmq_status().items()
               + test_zenoss_status().items()
               + test_openvpn_status().items()
               + test_zenoss_copyright('localhost').items()
               + aws_s3_mount_test().items()
               ))
        self.write(result)

