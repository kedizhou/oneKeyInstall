#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,yaml,os,time,sys,datetime

path=os.path.dirname(os.path.abspath(sys.argv[0]))
rpath=os.path.abspath(os.path.join(path,os.path.pardir))
minion=rpath+'/salt/jinja/script/minion_install/'
c=open(path+'/conf.json','r')

try:
	l=open(path+'/log.dat','a')
	f=open('/etc/salt/roster','w+')
except:
	print 'cannot create file: Permission denied:'+path
	sys.exit(9)
try:
	f.close
	x=yaml.load(c)
except:
	print 'parse file error.'
	sys.exit(9)

def clear():
	os.system('clear')

def w(log=''):
	l.write(time.strftime('%Y-%m-%d %H:%M:%S  ', time.localtime()))
	l.write(log+'\n')
	print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) ,log

def installMinionClient(serverName='', type='',password='',ipminion='',ipmaster='',allserver=''):
	try:
		cmds=[\
		"salt-ssh -i '"+type+"'  -r  'echo 1 > /tmp/lock'" ,\
		"salt-ssh -i '"+type+"'  -r  'mkdir -p /data/tools'" ,\
		"salt-ssh -i '"+type+"'  -r  \"echo server:"+ipmaster+" > /tmp/master && echo type:"+type+" >> /tmp/master && echo -e '"+allserver+"'> /tmp/setHost\"",\
		minion+"/sp -p '"+password+"' scp -r "+minion+"package/ "+ipminion+":/data/tools/",\
		minion+"/sp -p '"+password+"' scp "+minion+"install.sh "+ipminion+":/data/tools/package",\
		"salt-ssh -i '"+type+"'  -r  'source /etc/profile; /bin/bash /data/tools/package/install.sh'",\
		"salt-key -a '"+type+"' -y", \
		"salt-ssh -i '"+type+"'  -r  'echo 0 > /tmp/lock'" \
		]
		stdouts=[\
		":'"+serverName+"' create lock file.",\
		":'"+serverName+"' create work space successfull.",\
		":'"+serverName+"' write server ip address successfull.",\
		":'"+serverName+"' copy agent pack successfull.",\
		":'"+serverName+"' copy agent script successfull,and start install client,please wait.",\
		":'"+serverName+"' excute install script successfull.",\
		":'"+serverName+"' accept key from client.", \
		":'"+serverName+"' reset lock file."\
		]
		var=0
		for once in cmds:
			p=excuteShell(cmd=once,type=type)
			if re.search(ur'^salt-ssh.*',once):
				if p['retcode']:
					w(serverName+p['stderr']+p['stdout'])
					#sys.exit(12)
					raise
				else:
					w(stdouts[var]+' usage: '+str(p['tims'])+" s")
			else:
				w(p+stdouts[var])
			var+=1
		return 0
	except Exception, e:
		print e
		print p['stderr'],p['stdout']
		return 1
def excuteLocateShell(cmd=''):
	import commands
	while True:
		i = commands.getstatusoutput("source /etc/profile; "+cmd)
		if i[1].find('The function "state.sls" is running as')+1:
			w('has job is running.')
			time.sleep( 5 )
		else:
			break
	return i

def excuteShell(type='',cmd=''):
	'''
	'''
	if re.search(ur'^salt-ssh.*',cmd):
		cmd=cmd+' --out yaml'
	#r, w = os.pipe()
	import md5
	key = md5.new()
	key.update(cmd+str(datetime.datetime.now()))
	pipe_name = '/tmp/cmd_pipe_'+type+'_'+key.hexdigest()
	pid = os.fork()
	j=0
	if pid:
		while True:
			try:
				#result = os.waitpid(-1,os.WNOHANG)
				result = os.waitpid(pid,os.WNOHANG)
			except:
				pipe_r = open(pipe_name, 'r')
				#getback = pipe_r.readline()
				getback = pipe_r.read()
				os.remove(pipe_name)
				print '!'
				break
			print '.',
			j+=1
			time.sleep(1)
			sys.stdout.flush()
	else:
		pipe_w =  os.open(pipe_name,os.O_NONBLOCK |  os.O_CREAT | os.O_RDWR)
		getback=excuteLocateShell(cmd)
		os.write(pipe_w ,getback[1])
		sys.exit(0)

	try:
		y=yaml.load(getback)
		return {'retcode':y[type]['retcode'],'stderr':y[type]['stderr'],'stdout':y[type]['stdout'],'tims':j}
	except Exception,e:
		return getback

def killSignal(chars=''):
	getback=excuteLocateShell('salt \'*\' saltutil.is_running \'*\' --out yaml')
	#getback=excuteShell(cmd="source /etc/profile;salt '*' saltutil.is_running '*' --out yaml")
	try:
		y=yaml.load(getback[1])
		for type,value in y.iteritems():
			try:
				if value[0]['jid']:
					#print excuteShell(cmd="source /etc/profile;salt '*' saltutil.kill_job "+str(value[0]['jid']))
					excuteLocateShell('salt \'*\' saltutil.kill_job '+str(value[0]['jid']))
			except:
				pass
	except:
		pass
	
def writeRoster(id='localhost',ip='localhost',user='root',password='root'):
	f=open('/etc/salt/roster','a')
	f.write(id+':\n')
	f.write('  host: '+ip+'\n')
	f.write('  user: '+user+'\n')
	f.write('  passwd: '+password+'\n')
	f.write('  port: 22\n')
	f.write('  timeout: 300\n')
	f.close()

def pareResource(chars='',type=type):
	'''
	salt '*' saltutil.is_running state.highstate
	salt '*' saltutil.kill_job <job id>
	'''
	try:
		template=yaml.load(chars)
		for type_list,value_list in template[type].iteritems():
			if re.search(ur'cmd.*run',type_list) or re.search(ur'\_\|\-run',type_list):
				#print template['res_server'][type_list]['changes']['pid']
				try:
					return {'retcode':template[type][type_list]['changes']['retcode'],\
					'stderr':template[type][type_list]['changes']['stderr'],\
					'stdout':template[type][type_list]['changes']['stdout']}
				except:
					continue
			'''
			print type_list
			'''
	except:
		print 'analyze return result of install service error:'
		print ' content: '+chars
	# debug
	#sys.exit(0)

class serverCLass():
	def __int__(self):
		type=''
		server=''
	def createEnv(self):
		w(self.server+' stop iptables, mid:'+self.type)
		excuteShell(cmd="salt-ssh -i '"+self.type+"'  -r  'source /etc/profile;[ -e /var/lock/subsys/iptables ] && (iptables-save>/etc/sysconfig/iptables;/etc/init.d/iptables stop)'",type=self.type)
	def synModules(self):
		if self.testPing():
			sys.exit(9)
		#self.isRuning()
		w('synchronizing a module file to '+self.server+',mid: '+self.type+'just a moment please.')
		for i in range(1,3):
			excuteLocateShell("salt -t 60 -C 'L@"+self.type+"' saltutil.sync_modules --out yaml")
			time.sleep(2)
		w('In '+self.server+',mid: '+self.type+' to write host file.')
		excuteLocateShell("salt -t 60 -C 'L@"+self.type+"' setHost.set --out yaml")

	def restartMinion(self):
		w(self.server+' restart minion client, mid: "'+self.type+'".just a moment please.')
		excuteShell(cmd="salt-ssh -i '"+self.type+"'  -r  'source /etc/profile;/etc/init.d/salt-minion restart'",type=self.type)
		time.sleep(5)

	def foundMinionKey(self,count=0):
		key=yaml.load(excuteLocateShell("salt-key -l un --out yaml")[1])
		try:
			if self.type in key['minions_pre'] and key['minions_pre']:
				excuteLocateShell("salt-key -a '"+self.type+"' -y")
				w(self.server+': input key to salt container successfull.mid: '+self.type)
				#break
			else:
				print self.server+': found key timeout ',count,'.Just a moment please.mid: '+self.type
				self.restartMinion()
			#time.sleep(5)
		except Exception, e:
			print e
			print self.server+": not found minion key.mid: "+self.type+", message:",key, e
			pass

	def testPing(self):
		y=1
		while 1:
			t=excuteLocateShell("salt -t 300 -C 'L@"+self.type+"' test.ping --out yaml")
			try:
				if yaml.load(t[1])[self.type]:
					#print 'connect to "' + self.server+'" server is ok.'
					#break
					return 0
			except Exception, e:
				print 'connect to '+self.server+",and mid: '"+self.type+"' timout.",y
				#excuteShell(cmd="salt-ssh -i '"+self.type+"'  -r  'source /etc/profile;/etc/init.d/salt-minion restart'",type=self.type)
				#maybe minion client process is down
				#self.restartMinion()
				#maybe key in un,not in acc
				self.foundMinionKey(count=y)
				pass
			if y > 6:
				print "connect server "+self.server+",mid: "+self.type+" unreachable.error message:"+t[1]+".has "+str(y)+" number of times to try again."
				print "you may be execute command:  salt-key -d "+self.type+" -y"
				print "and re-install try again latter."
				#sys.exit(9)
				return 1
			y+=1
	def installService(self,list=''):
		global queue
		#for service in list:
		for serviceN in range(1,len(queue[self.type])):
			service=queue[self.type][serviceN]
			if self.testPing():
				sys.exit(9)
			queue[self.type][0]=1
			#self.isRuning()
			#w(self.server+' sync grains data')
			#self.synModules()
			w(self.server+' start install '+service+'.mid: '+self.type)
			starttime = datetime.datetime.now()
			i_service = excuteShell(cmd="salt -t 3600 -C 'L@"+self.type+"' state.sls spfile.install."+service+' --out yaml',type=self.type)
			endtime = datetime.datetime.now()
			template=pareResource(chars=i_service,type=self.type)
			try:
				if template['retcode']:
					w(self.server+' install service, mid: '+self.type+', return code:'+template['retcode'])
					pass
			except:
				#print service+', error message return full: '+i_service
				w(self.server+' install "'+service+'" failed.mid: '+self.type+', error message return full: '+i_service)
				queue[self.type][0]=2
				sys.exit(11)
			w(self.server+' install "'+service+'" successful,mid: '+self.type+'.usage '+str((endtime - starttime).seconds)+"s")
		queue[self.type][0]=2
	def configService(self,list=''):
		#for config in list:
		if self.testPing():
			sys.exit(9)
		#self.isRuning()
		w(self.server+' configuration service,mid: '+self.type+', please wait ...')
		starttime = datetime.datetime.now()
		c_service = excuteShell(cmd="salt -t 1800 -C 'L@"+self.type+"' state.sls spfile.conf."+self.server+' --out yaml',type=self.type)
		endtime = datetime.datetime.now()
		template=pareResource(chars=c_service,type=self.type)
		try:
			if template['retcode']:
				pass
		except:
			#w(self.type+' configuration the service failed.'+template['stderr']+template['stdout'])
			w(self.server+' configuration the service failed.mid: '+self.type+'. error content:'+c_service)
			sys.exit(11)
		w(self.server+' configuration  the service successful, mid: '+self.type+'.usage '+str((endtime - starttime).seconds)+"s")
	def appPublish(self):
		if self.testPing():
			sys.exit(9)
		#self.isRuning()
		w(self.server+' publish application.')
		starttime = datetime.datetime.now()
		c_service = excuteShell(cmd="salt -t 1800 -C 'L@"+self.type+"' state.sls spfile.publish."+self.server+' --out yaml',type=self.type)
		endtime = datetime.datetime.now()
		template=pareResource(chars=c_service,type=self.type)
		'''
		try:
			if template['retcode']:
				pass
		except:
			w(self.server+' publish application failed.'+c_service)
			sys.exit(11)
		'''
		w(self.server+' publish application  successful,mid: '+self.type+'.usage '+str((endtime - starttime).seconds)+"s")
	def delkey(self):
		try:
			for role in ['acc','un','rej']:
				t=yaml.load(excuteLocateShell("salt-key -l "+role+" --out yaml")[1])
				for key,value in t.iteritems():
					if self.type in value:
						excuteLocateShell("salt-key -d "+self.type+" -y --out yaml")
						print "delete key of not use that's successful.mid: ",self.type
		except:
			pass
	def isRuning(self):
		while True:
			y=excuteLocateShell("salt-run -t 1800 jobs.active")[1]
			if y.find('L@'+self.type)+1:
				print self.server+' Has job  is not complete.mid: '+self.type+', please wait ...'
				time.sleep(5)
			else:
				break
		
def probeMinion(serverAllFunction,v):
	global queue
	check_s = excuteShell(cmd="salt-ssh -i '"+serverAllFunction.type+"' -r 'ls /etc/salt/minion'",type=serverAllFunction.type)
	check_i = check_s['retcode']
		
	#if excuteShell(cmd="salt-ssh -i '"+serverAllFunction.type+"' -r 'ls /etc/salt/minion'",type=serverAllFunction.type)['retcode'] \
	if check_i \
	and excuteShell(cmd="salt-ssh -i '"+serverAllFunction.type+"' -r grep '1' /tmp/lock" ,type=serverAllFunction.type)['retcode']:
		queue[serverAllFunction.type].extend( v['service'] )
		'''
		server need install minion client.
		'''
		w( serverAllFunction.server+' server need install minion clinet,mid: '+serverAllFunction.type )
		if installMinionClient(serverName=serverAllFunction.server, type=serverAllFunction.type,password=v['password'],ipminion=v['ip'],ipmaster=v['ipmaster'],allserver=v['allserver']):
			#w('install minion client failed.')
			return -1
		else:
			serverAllFunction.delkey()
			p=1
			'''
			wait client to do that input key into salt-master.
			'''
			try:
				while 1:
					if serverAllFunction.type in yaml.load(excuteLocateShell("salt-key -l acc --out yaml")[1])['minions']:
						#w('install minion client successfull.')
						return 0
					'''
					try find key input to salt container
					'''
					serverAllFunction.foundMinionKey(count=p)
					if p>=6:
						w(serverAllFunction.server+' install client encounter error,please close you iptables.a1,mid: '+serverAllFunction.type)
						return -1
					p+=1
			except Exception, e:
				print e
				w(serverAllFunction.server+' install client encounter error,please close you iptables.a2,mid: '+serverAllFunction.type)
				return -1
					
	else:
		'''
		minion has installed or installing.
		'''
		while excuteShell(cmd = "salt-ssh -i '"+serverAllFunction.type+"'  -r grep '1' /tmp/lock" ,type=serverAllFunction.type)['retcode'] == 0:
			time.sleep(5)
			w( serverAllFunction.server+': wait other thread install minion client.mid: '+serverAllFunction.type )
		print serverAllFunction.server+': minion has installed,mid: '+serverAllFunction.type
		m=excuteShell(cmd="salt-ssh -i '"+serverAllFunction.type+"'  -r  'grep \'^id:\ \' /etc/salt/minion | cut -d\" \" -f 2'",type=serverAllFunction.type)
		if not  m['retcode']:
			serverAllFunction.type= m['stdout'].split("\n")[1]
			queue[serverAllFunction.type].extend( v['service'] )
			#print serverAllFunction.type,'--------------',queue
			try:
				assert ( len( queue[serverAllFunction.type] ) == len(v['service'])+1 )
			except:
				#while queue[serverAllFunction.type][0] < 2:
				while True:
					if queue[serverAllFunction.type][0] == 1:
						return 1
					else:
						time.sleep( 5 )
						w( serverAllFunction.server+': wait service type '+serverAllFunction.type+' start then put over this client minion thread.' )
		else:
			w(serverAllFunction.server+' minion configure error in /etc/salt/minion ,example: "id: xxx",mid: '+serverAllFunction.type)
			#sys.exit(12)
			return -1
		return 0


def i(serverAllFunction,v):
	global queue
	'''
	crate environment
	'''
	serverAllFunction.createEnv()
	'''
	install minion
	'''
	i = probeMinion(serverAllFunction,v)
	if i == -1:
		w(serverAllFunction.server+': install minion client failed.mid: '+serverAllFunction.type)
		excuteLocateShell(" salt-ssh -i '"+serverAllFunction.type+"'  -r  'echo 0 > /tmp/lock'" )
		sys.exit(9)
	elif i == 0:
		w(serverAllFunction.server+': install minion client successfull.mid: '+serverAllFunction.type)
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
		#serverAllFunction.installService( v['service'] )
		serverAllFunction.installService(queue[serverAllFunction.type])
	elif i == 1:
		while True:
			if queue[serverAllFunction.type][0] == 2:
				break
			time.sleep( 5 )
			w( 'merge install service job.' )
			
	#print 'queue:',queue
	'''
	configuration service
	'''
	serverAllFunction.configService( v['service'] )
	'''
	publish app service
	'''
	serverAllFunction.appPublish()
def main(ip=''):
	global queue
	assert (re.search(ur'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',ip)), 'input ip address error.'
	#import pdb
	#pdb.set_trace()
	l=''
	#thread pools
	threads = []
	for type, v in  x.iteritems(): #get server list
		#l=l+type+':'+v['ip']+'|'
		l=l+v['alias']+':'+v['ip']+'|'
		if type == 'db_server':
			try:
				f=open('/data/salt/base/pillar/db_server.sls','a')
				f.write('db_server:\n')
				f.write('  port: '+str( v['port'] )+'\n')
				f.write('  instance: '+v['instance']+'\n')
				f.write('  username: '+v['username']+'\n')
				f.write('  password: '+v['password']+'\n')
				f.close()
			except Exception,e:
				w("write db_server.sls failed, maybe direcotry not exist '/data/salt/base/pillar/'.")
				print e
				sys.exit(90)

	for type, v in  x.iteritems(): #get server list
		if type == 'db_server':
			continue
		serverAllFunction=serverCLass()
		writeRoster(type,v['ip'],v['user'],v['password'])
		serverAllFunction.server=type
		serverAllFunction.type=type
		queue[type]=[0]
		#sync install, configure, publish service
		#password=v['password'],ipminion=v['ip'],ipmaster=ip,allserver=l
		import threading
		v['ipmaster']=ip
		v['allserver']=l
		z = threading.Thread(target=i, args=(serverAllFunction,v))
		threads.append(z)

	for t in threads:
		t.start()
		time.sleep( 30 )
	#print 'wait all thread excute the end.'
	for t in threads:
		t.join()
	while True:
		active = excuteLocateShell('salt-run jobs.active')[1]
		if active == '' or active.find('No minions matched the target.')+1:
		#if excuteLocateShell('salt-run jobs.active')[1] == '':
			'''
			clean environment and start iptables
			'''
			for type, v in  x.iteritems(): #get server list
				w( type+' stop salt service.' )
				excuteShell(cmd="salt-ssh -i '"+type+"'  -r  '/etc/init.d/salt-minion stop'",type=type)
			print 'great! install successfull, please start iptables according to nedds by your hands.'
			break
		else:
			print 'The install thread is not complete.please wait ...'
			time.sleep(5)
			

if __name__ == '__main__':
	queue={}
	#if re.search(ur'server\d+','server1'):
	w('save and stop iptables')
	excuteLocateShell(cmd='[ -e /var/lock/subsys/iptables ] && (iptables-save>/etc/sysconfig/iptables;/etc/init.d/iptables stop)')
	clear()
	w('clean installation environment,please wait')
	killSignal()
	w('clean installation environment over,startup install  process.')
	if not os.path.exists('/etc/salt/'):
		excuteLocateShell(cmd='mkdir /etc/salt')
	import platform
	assert( platform.dist()[0].upper() in ['CENTOS','REDHAT'] ) ,"OneKey Installer support only 'centos' or 'redhat' os."
	t=excuteLocateShell(cmd="ifconfig eth0 | grep 'inet addr' | awk '{print $2}' | cut -d: -f2")[1]
	ip=raw_input("please input master control server IP address.("+t+")[y]:")
	if ip.upper() == 'Y':
		main(t)
	else:
		main(ip)
	w('start iptables.')
	excuteLocateShell(cmd='sleep 60 && /etc/init.d/iptables start')
	c.close()
	l.close()
	os.remove('/data/salt/base/pillar/db_server.sls')
