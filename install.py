# -*- encoding: utf8 -*-
__author__ = 'kedi'

import re
import yaml
import os
import time
import sys
import datetime
import platform
import threading
import salt.client as client
import socket

path = os.path.dirname(os.path.abspath(sys.argv[0]))
rpath = os.path.abspath(os.path.join(path, os.path.pardir))
minion = rpath + '/salt/jinja/script/minion_install/'


class common():
    def __init__(self):
        pass

    @classmethod
    def clear(self):
        os.system('clear')

    @classmethod
    def probePort(self, host='1.1.1.1', port='22', passwd='', type=''):
        remote_ip = host
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            w(log='Failed to create socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1])
            return False
        s.settimeout(5)
        if not re.findall(r'\d+.\d+.\d+.\d+', host):
            try:
                socket.setdefaulttimeout(5)
                remote_ip = socket.gethostbyname(host)
            except socket.gaierror:
                w(log='Hostname could not be resolved. Exiting')
                return False
        try:
            s.connect((remote_ip, int(port)))
            s.shutdown(2)
            s.close()
            # return True
        except Exception, e:
            w('connect to server: ' + host + ' timeout.')
            return False
        if excuteShell(cmd=minion + "/sp -p '" + passwd + "' ssh -o ConnectTimeout=3 " + remote_ip + " '>/tmp/lock'",
                       type=type).lower().find('denied') + 1:
            w('Ssh connect server ip: ' + host + ',permission denied, please check passwd and try again.')
            return False
        else:
            return True


def w(log=''):
    l.write(time.strftime('%Y-%m-%d %H:%M:%S  ', time.localtime()))
    l.write(log + '\n')
    print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), log


def installMinionClient(serverName='', type='', password='', ipminion='', ipmaster='', allserver=''):
    try:
        cmds = [ \
            "salt-ssh -i '" + type + "'  -r  'echo 1 > /tmp/lock'", \
            "salt-ssh -i '" + type + "'  -r  'mkdir -p /data/tools'", \
            "salt-ssh -i '" + type + "'  -r  \"echo server:" + ipmaster + " > /tmp/master && echo type:" + type + " >> /tmp/master && echo -e '" + allserver + "'> /tmp/setHost\"", \
            minion + "/sp -p '" + password + "' scp -r " + minion + "package/ " + ipminion + ":/data/tools/", \
            minion + "/sp -p '" + password + "' scp " + minion + "install.sh " + ipminion + ":/data/tools/package", \
            "salt-ssh -i '" + type + "'  -r  'source /etc/profile; /bin/bash /data/tools/package/install.sh'", \
            "salt-key -a '" + type + "' -y", \
            "salt-ssh -i '" + type + "'  -r  'echo 0 > /tmp/lock'" \
            ]
        stdouts = [ \
            ":'" + serverName + "' create lock file.", \
            ":'" + serverName + "' create work space successfull.", \
            ":'" + serverName + "' write server ip address successfull.", \
            ":'" + serverName + "' copy agent pack successfull.", \
            ":'" + serverName + "' copy agent script successfull,and start install client,please wait.", \
            ":'" + serverName + "' excute install script successfull.", \
            ":'" + serverName + "' accept key from client.", \
            ":'" + serverName + "' reset lock file." \
            ]
        var = 0
        for once in cmds:
            p = excuteShell(cmd=once, type=type)
            if re.search(ur'^salt-ssh.*', once):
                if p['retcode']:
                    w(serverName + p['stderr'] + p['stdout'])
                    # sys.exit(12)
                    raise
                else:
                    w(stdouts[var] + ' usage: ' + str(p['tims']) + " s")
            else:
                w(p + stdouts[var])
            var += 1
        return 0
    except Exception, e:
        print 'install minion client failed:', e, p['stderr'], p['stdout']
        return 1


def excuteLocateShell(cmd=''):
    import commands
    while True:
        i = commands.getstatusoutput("source /etc/profile; " + cmd)
        if i[1].find('The function "state.sls" is running as') + 1:
            try:
                w('has job is running.')
            except:
                print 'has job is running.'
                pass
            time.sleep(5)
        else:
            break
    return i


def excuteShell(type='', cmd=''):
    '''
    '''
    if re.search(ur'^salt-ssh.*', cmd):
        cmd = cmd + ' --out yaml'
    # r, w = os.pipe()
    import md5
    key = md5.new()
    key.update(cmd + str(datetime.datetime.now()))
    pipe_name = '/tmp/cmd_pipe_' + type + '_' + key.hexdigest()
    pid = os.fork()
    j = 0
    if pid:
        while True:
            try:
                # result = os.waitpid(-1,os.WNOHANG)
                result = os.waitpid(pid, os.WNOHANG)
            except:
                pipe_r = open(pipe_name, 'r')
                # getback = pipe_r.readline()
                getback = pipe_r.read()
                os.remove(pipe_name)
                # 显示进度 0
                # print '!'
                break
            # 显示进度 1
            # print '.',
            j += 1
            time.sleep(1)
            sys.stdout.flush()
    else:
        pipe_w = os.open(pipe_name, os.O_NONBLOCK | os.O_CREAT | os.O_RDWR)
        getback = excuteLocateShell(cmd)
        os.write(pipe_w, getback[1])
        sys.exit(0)

    try:
        y = yaml.load(getback)
        return {'retcode': y[type]['retcode'], 'stderr': y[type]['stderr'], 'stdout': y[type]['stdout'], 'tims': j}
    except Exception, e:
        return getback


def killSignal(chars=''):
    getback = excuteLocateShell('salt \'*\' saltutil.is_running \'*\' --out yaml')
    # getback=excuteShell(cmd="source /etc/profile;salt '*' saltutil.is_running '*' --out yaml")
    try:
        y = yaml.load(getback[1])
        for type, value in y.iteritems():
            try:
                if value[0]['jid']:
                    # print excuteShell(cmd="source /etc/profile;salt '*' saltutil.kill_job "+str(value[0]['jid']))
                    excuteLocateShell('salt \'*\' saltutil.kill_job ' + str(value[0]['jid']))
            except:
                pass
    except:
        pass


def writeRoster(id='localhost', ip='localhost', user='root', password='root'):
    f = open('/etc/salt/roster', 'a')
    f.write(id + ':\n')
    f.write('  host: ' + ip + '\n')
    f.write('  user: ' + user + '\n')
    f.write('  passwd: ' + password + '\n')
    f.write('  port: 22\n')
    f.write('  timeout: 300\n')
    f.close()


def pareResource(chars='', type=type):
    '''
    salt '*' saltutil.is_running state.highstate
    salt '*' saltutil.kill_job <job id>
    '''
    try:
        template = yaml.load(chars)
        for type_list, value_list in template[type].iteritems():
            if re.search(ur'cmd.*run', type_list) or re.search(ur'\_\|\-run', type_list):
                # print template['res_server'][type_list]['changes']['pid']
                try:
                    return {'retcode': template[type][type_list]['changes']['retcode'], \
                            'stderr': template[type][type_list]['changes']['stderr'], \
                            'stdout': template[type][type_list]['changes']['stdout']}
                except:
                    continue
            '''
            print type_list
            '''
    except:
        print 'analyze return result of install service error:'
        print ' content: ' + chars
        # debug
        # sys.exit(0)


class serverCLass():
    def __int__(self):
        self.type = ''
        self.server = ''
        self.v = {}

    def createEnv(self):
        w(self.server + ' stop iptables, mid:' + self.type)
        excuteShell(
            cmd="salt-ssh -i '" + self.type + "'  -r  'source /etc/profile;[ -e /var/lock/subsys/iptables ] && (iptables-save>/etc/sysconfig/iptables;/etc/init.d/iptables stop)'",
            type=self.type)

    def synModules(self):
        if self.testPing():
            sys.exit(9)
        # self.isRuning()
        w('synchronizing a module file to ' + self.server + ',mid: ' + self.type + 'just a moment please.')
        for i in range(1, 3):
            excuteLocateShell("salt -t 60 -C 'L@" + self.type + "' saltutil.sync_modules --out yaml")
            time.sleep(2)
        w('In ' + self.server + ',mid: ' + self.type + ' to write host file.')
        excuteLocateShell("salt -t 60 -C 'L@" + self.type + "' setHost.set --out yaml")

    def restartMinion(self):
        import signal
        print "Server name:'" + self.server + "' restart minion client, mid: '" + self.type + "'."
        pid = os.fork()
        if pid:
            i = 0
            time.sleep(5)
            w("Server name:'" + self.server + "' restart minion client command has send.")
            while True:
                try:
                    result = os.waitpid(pid, os.WNOHANG)
                except:
                    print 'restart minion client successfull,and soon. :)'
                    break

                r = excuteLocateShell(cmd=minion + "/sp -p '" + self.v['password'] + "' ssh " + self.v[
                    'ip'] + ' ps -ef | grep salt-minion | grep -v grep | awk \'{print $2}\'')
                if r[0] == 0:
                    print 'restart minion client successfull,minion client pid:' + str(r[1])
                    os.kill(pid, signal.SIGTERM)
                    break
                if i > 10:
                    print 'restart minion client failed.', r
                    os.kill(pid, signal.SIGTERM)
                    break
                time.sleep(1)
                i += 1
        else:
            w("Server name:'" + self.server + "' restart minion client, mid: '" + self.type \
              + "'.just a moment please.create task pid: " + str(os.getpid()))
            excuteLocateShell(minion + "/sp -p '" + self.v['password'] + "' ssh " + self.v['ip'] \
                              + " 'source /etc/profile;/etc/init.d/salt-minion restart'")

    def foundMinionKey(self, count=0):
        key = yaml.load(excuteLocateShell("salt-key -l un --out yaml")[1])
        try:
            if self.type in key['minions_pre'] and key['minions_pre']:
                excuteLocateShell("salt-key -a '" + self.type + "' -y")
                w("Server name:'" + self.server + "': input key to salt container successfull.mid: " + self.type)
            # break
            else:
                print "Server name:'" + self.server + "': found key timeout ", count, '.Just a moment please.mid: ' + self.type
                self.restartMinion()
                # time.sleep(5)
        except Exception, e:
            print e
            print "Server name:'" + self.server + "': not found minion key.mid: " + self.type + ", message:", key, e
            pass

    def testPing(self):
        y = 1
        print "Test connect server: '" + self.server + "',mid: '" + self.type + "'."
        c = client.LocalClient()
        while 1:
            # t = excuteLocateShell("salt -t 300 -C 'L@" + self.type + "' test.ping --out yaml")
            try:
                # if yaml.load(t[1])[self.type]:
                if c.cmd(self.type, 'test.ping')[self.type]:
                    print 'Connect to "' + self.server + '" server is ok,and mid:' + self.type
                    # break
                    return 0
            except Exception, e:
                print 'Connect to ' + self.server + ",and mid: '" + self.type + "' timout.", y
                # excuteShell(cmd="salt-ssh -i '"+self.type+"'  -r  'source /etc/profile;/etc/init.d/salt-minion restart'",type=self.type)
                # maybe minion client process is down
                # self.restartMinion()
                # maybe key in un,not in acc
                pass
            if y > 5 and y <= 8:
                self.foundMinionKey(count=y)
            elif y > 8:
                print "Connect server " + self.server + ",mid: " + self.type + " unreachable,please check iptables."
                print "you may be execute command:  salt-key -d " + self.type + " -y"
                print "and re-install try again latter."
                # sys.exit(9)
                return 1
            y += 1

    def installService(self):
        global queue
        # for service in list:
        # for serviceN in range(1, len(queue[self.type])):
        queue[self.type][0] = 1
        for serviceN in queue[self.type]:
            if serviceN == 1:
                continue
            time.sleep(2)
            # service = queue[self.type][serviceN]
            service = serviceN
            print 'Minion client \'' + self.type + '\' install service list:' + str(
                queue[self.type]) + ', now installing: ' + service

            if self.testPing():
                sys.exit(9)
            # self.isRuning()
            # w(self.server+' sync grains data')
            # self.synModules()
            w("Server name:'" + self.server + "' start install " + service + '.mid: ' + self.type)
            starttime = datetime.datetime.now()
            i_service = excuteShell(
                cmd="salt -t 3600 -C 'L@" + self.type + "' state.sls spfile.install." + service + ' --out yaml',
                type=self.type)
            endtime = datetime.datetime.now()
            template = pareResource(chars=i_service, type=self.type)
            try:
                if template['retcode']:
                    w("Server name:'" + self.server + "' install service, mid: " + self.type + ', return code:' +
                      template['retcode'])
                    pass
            except:
                # print service+', error message return full: '+i_service
                w("Server name:'" + self.server + '\' install "' + service + '" failed.mid: ' + \
                  self.type + ', error message return full: ' + i_service)
                queue[self.type][0] = 2
                sys.exit(11)
            w("Server name:'" + self.server + '\' install "' + service + '" successful,mid: ' + \
              self.type + '.usage ' + str((endtime - starttime).seconds) + "s")
        queue[self.type][0] = 2

    def configService(self):
        # for config in list:
        if self.testPing():
            sys.exit(9)
        # self.isRuning()
        w("Server name:'" + self.server + '\' configuration service,mid: ' + self.type + ', please wait ...')
        starttime = datetime.datetime.now()
        c_service = excuteShell(
            cmd="salt -t 1800 -C 'L@" + self.type + "' state.sls spfile.conf." + self.server + ' --out yaml',
            type=self.type)
        endtime = datetime.datetime.now()
        template = pareResource(chars=c_service, type=self.type)
        try:
            if template['retcode']:
                pass
        except:
            # w(self.type+' configuration the service failed.'+template['stderr']+template['stdout'])
            w("Server name:'" + self.server + '\' configuration the service failed.mid: ' + \
              self.type + '. error content:' + c_service)
            sys.exit(11)
        w("Server name:'" + self.server + '\' configuration  the service successful, mid: ' + \
          self.type + '.usage ' + str((endtime - starttime).seconds) + "s")

    def appPublish(self):
        if self.testPing():
            sys.exit(9)
        # self.isRuning()
        w(self.server + ' publish application.')
        starttime = datetime.datetime.now()
        c_service = excuteShell(
            cmd="salt -t 1800 -C 'L@" + self.type + "' state.sls spfile.publish." + self.server + ' --out yaml',
            type=self.type)
        endtime = datetime.datetime.now()
        template = pareResource(chars=c_service, type=self.type)
        '''
        try:
            if template['retcode']:
                pass
        except:
            w(self.server+' publish application failed.'+c_service)
            sys.exit(11)
        '''
        w(self.server + ' publish application  successful,mid: ' + self.type + '.usage ' + str(
            (endtime - starttime).seconds) + "s")

    def delkey(self):
        w('re-install minion client: ' + self.type + ' ,delete key of not use key.')
        try:
            for role in ['acc', 'un', 'rej']:
                t = yaml.load(excuteLocateShell("salt-key -l " + role + " --out yaml")[1])
                for key, value in t.iteritems():
                    if self.type in value:
                        excuteLocateShell("salt-key -d " + self.type + " -y --out yaml")
                        print "delete key of not use that's successful.mid: ", self.type
        except:
            pass

    def isRuning(self):
        while True:
            y = excuteLocateShell("salt-run -t 1800 jobs.active")[1]
            if y.find('L@' + self.type) + 1:
                print self.server + ' Has job  is not complete.mid: ' + self.type + ', please wait ...'
                time.sleep(5)
            else:
                break

    def probeMinion(self):
        global queue
        check_s = excuteShell(
            cmd="salt-ssh -i '" + self.type + "' -r \"grep -oP '(?<=id:\ ).*$' /etc/salt/minion\"",
            type=self.type)
        check_i = check_s['retcode']

        '''
        server need install minion client.
        '''
        # if excuteShell(cmd="salt-ssh -i '"+self.type+"' -r 'ls /etc/salt/minion'",type=self.type)['retcode'] \
        if check_i \
                and excuteShell(cmd="salt-ssh -i '" + self.type + "' -r grep '1' /tmp/lock",
                                type=self.type)['retcode']:
            queue[self.type].extend(self.v['service'])

            w("Server name:'" + self.server + "' server need install minion clinet,mid: " + self.type)
            self.delkey()
            if installMinionClient(serverName=self.server, type=self.type,
                                   password=self.v['password'],
                                   ipminion=self.v['ip'], ipmaster=self.v['ipmaster'], allserver=self.v['allserver']):
                # w('install minion client failed.')
                return -1
            else:
                # serverAllFunction.delkey()
                p = 1
                '''
                wait client to do that input key into salt-master.
                '''
                try:
                    while 1:
                        if self.type in yaml.load(excuteLocateShell("salt-key -l acc --out yaml")[1])[
                            'minions']:
                            # w('install minion client successfull.')
                            return 0
                        '''
                        try find key input to salt container
                        '''
                        self.foundMinionKey(count=p)
                        if p >= 6:
                            w(
                                "Server name:'" + self.server + "' install client encounter error,please close you iptables.a1,mid: " + self.type)
                            return -1
                        p += 1
                except Exception, e:
                    print e
                    w(
                        "Server name:'" + self.server + "' install client encounter error,please close you iptables.a2,mid: " + self.type)
                    return -1

        else:
            '''
            minion client installing.
           '''
            k = 0
            while excuteShell(cmd="salt-ssh -i '" + self.type + "'  -r grep '1' /tmp/lock",
                              type=self.type)['retcode'] == 0:
                time.sleep(5)
                k += 1
                if k % 10 == 0:
                    w(
                        "Server name:'" + self.server + "': wait other thread install minion client.mid: " + self.type)

            m = excuteShell(
                cmd="salt-ssh -i '" + self.type + "'  -r  \"grep -oP '(?<=id:\ ).*$' /etc/salt/minion\"",
                type=self.type)
            '''
            minion client has installed
           '''
            print "Server name:'" + self.server + "': minion has installed,mid: " + m['stdout'].split("\n")[1]
            if not m['retcode']:
                self.type = m['stdout'].split("\n")[1]
                # 在正在运行的队列中加入新任务
                if rlock.acquire(1):
                    print "Server name:'" + self.server + "' ,Add task " + str(
                        self.v['service']) + ' to dict: ' + self.type
                    queue[self.type].extend(self.v['service'])
                    rlock.release()
                else:
                    print 'Add task to list failed.'
                    return -2
                # print self.type,'--------------',queue
                try:
                    assert (len(queue[self.type]) == len(self.v['service']) + 1)
                except:
                    k = 0
                    while True:
                        if queue[self.type][0] == 1:
                            return 1
                        elif queue[self.type][0] == -1:
                            return -2
                        else:
                            time.sleep(1)
                            k += 1
                            if k % 20 == 0:
                                w(
                                    "Server name:'" + self.server + "': wait service type " + self.type + ',install service start.')
            else:
                w(
                    "Server name:'" + self.server + "' minion configure error in /etc/salt/minion ,example: 'id: xxx',mid: " + self.type)
                # sys.exit(12)
                return -1
            return 0


def i(serverAllFunction):
    global queue
    '''
    crate environment
    '''
    serverAllFunction.createEnv()
    '''
    install minion
    '''
    i = serverAllFunction.probeMinion()
    if i == -1:
        w(
            "Server name: '" + serverAllFunction.server + "': install minion client failed.mid: " + serverAllFunction.type)
        excuteLocateShell(" salt-ssh -i '" + serverAllFunction.type + "'  -r  'echo 0 > /tmp/lock'")
        sys.exit(9)
    elif i == 0:
        w(
            "Server name: '" + serverAllFunction.server + "' install minion client successfull.mid: " + serverAllFunction.type)
        '''
        type
        serverAllFunction.type=type
        '''
        '''
        write hosts file.
        '''
        serverAllFunction.synModules()
        '''
        insert service
        '''
        # serverAllFunction.installService( self.v['service'] )
        serverAllFunction.installService()
    elif i == 1:
        p = 0
        while True:
            if queue[serverAllFunction.type][0] == 2:
                break
            time.sleep(10)
            if p % 10 == 0:
                w('merge install service job.')
            p += 1
    elif i == -2:
        return False

    # print 'queue:',queue
    '''
    configuration service
    '''
    serverAllFunction.configService()
    '''
    publish app service
    '''
    serverAllFunction.appPublish()


def main():
    global queue
    l = ''
    ip = ''
    # thread pools
    threads = []
    probe = 0


    # import pdb
    # pdb.set_trace()
    print '-' * 120
    print "|", 'One key install "xxxxx platform"'
    print "|", ' ' * 20, 'xxxxxx'
    print '-' * 120
    print "|%-20s|%-20s|%-60s" % ('Server name', 'Ip address', 'Service list')

    for type, v in x.iteritems():  # get server list
        # l=l+type+':'+self.v['ip']+'|'
        l = l + v['alias'] + ':' + v['ip'] + '|'
        if type == 'db_server':
            try:
                f = open('/data/salt/base/pillar/db_server.sls', 'a')
                f.write('db_server:\n')
                f.write('  port: ' + str(v['port']) + '\n')
                f.write('  instance: ' + v['instance'] + '\n')
                f.write('  username: ' + v['username'] + '\n')
                f.write('  password: ' + v['password'] + '\n')
                f.close()
            except Exception, e:
                w("Write db_server.sls failed, maybe direcotry not exist '/data/salt/base/pillar/'.")
                print e
                sys.exit(90)
        else:
            print '-' * 120
            print "|%-20s|%-20s|%-60s" % (type, v['ip'], v['service'])
    print '-' * 120

    t = excuteLocateShell(cmd="ifconfig eth0 | grep -oP '[.\d]+(?=\  Bcast)'")[1]
    ip = raw_input("please input master control server IP address.(" + t + ")[y]:")
    if ip.upper() == 'Y':
        # main(t)
        ip = t

    try:
        assert (re.search(ur'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip)), 'input ip address error.'
    except Exception, e:
        print e
        exit(9)
    common.clear()
    for type, v in x.iteritems():  # get server list
        if type == 'db_server':
            continue
        serverAllFunction = serverCLass()
        writeRoster(type, v['ip'], v['user'], v['password'])
        serverAllFunction.server = type
        serverAllFunction.type = type
        queue[type] = [0]
        # sync install, configure, publish service
        # password=self.v['password'],ipminion=self.v['ip'],ipmaster=ip,allserver=l
        v['ipmaster'] = ip
        if not common.probePort(v['ip'], port=22, passwd=v['password'], type=type):
            probe = 1
        v['allserver'] = l
        serverAllFunction.v = v
        z = threading.Thread(target=i, args=(serverAllFunction,))
        threads.append(z)

    if probe == 1:
        exit(0)

    for t in threads:
        t.start()
        time.sleep(10)
    # print 'wait all thread excute the end.'
    for t in threads:
        t.join()
    while True:
        active = excuteLocateShell('salt-run jobs.active')[1]
        if active == '' or active.find('No minions matched the target.') + 1:
            # if excuteLocateShell('salt-run jobs.active')[1] == '':
            '''
            clean environment and start iptables
          '''
            for type, v in x.iteritems():  # get server list
                w(type + ' stop salt service.')
                excuteShell(cmd="salt-ssh -i '" + type + "'  -r  '/etc/init.d/salt-minion stop'", type=type)
            break
        else:
            print 'The install thread is not complete.please wait ...'
            time.sleep(5)


try:
    f = open('/etc/salt/roster', 'w+')
    f.close
except:
    print 'cannot create file: Permission denied: /etc/salt/roster'
    sys.exit(9)

try:
    l = open(path + '/log.dat', 'a')
except:
    print 'cannot create file: Permission denied: ' + path + '/log.dat'
    sys.exit(9)

try:
    c = open(path + '/conf.json', 'r')
    x = yaml.load(c)
except:
    print 'parse file error.'
    sys.exit(9)

if __name__ == '__main__':
    queue = {}
    common.clear()
    rlock = threading.RLock()
    # if re.search(ur'server\d+','server1'):
    excuteLocateShell(cmd='/etc/init.d/salt-master restart')
    time.sleep(2)
    w('Please wait for save and stop iptables.')
    excuteLocateShell(
        cmd='[ -e /var/lock/subsys/iptables ] && (iptables-save>/etc/sysconfig/iptables;/etc/init.d/iptables stop)')
    common.clear()
    w('Clean installation environment,please wait.')
    killSignal()
    w('Clean installation environment end,startup install process.')
    if not os.path.exists('/etc/salt/'):
        excuteLocateShell(cmd='mkdir /etc/salt')
    assert (
        platform.dist()[0].upper() in ['CENTOS', 'REDHAT']), "OneKey Installer support only 'centos' or 'redhat' os."
    common.clear()
    # t = excuteLocateShell(cmd="ifconfig eth0 | grep -oP '[.\d]+(?=\  Bcast)'")[1]
    # common.clear()
    # ip = raw_input("please input master control server IP address.(" + t + ")[y]:")
    # if ip.upper() == 'Y':
    #     main(t)
    # else:
    #     main(ip)
    main()
    w('Please wait for startup iptables.')
    excuteLocateShell(cmd='sleep 10 && /etc/init.d/iptables start')
    c.close()
    l.close()
    os.remove('/data/salt/base/pillar/db_server.sls')
    print 'great! install successfull, please start iptables according to nedds by your hands.'
