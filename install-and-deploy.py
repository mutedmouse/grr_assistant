#!/usr/bin/python
#############################################################
#  Created by frosty_1313 and Grimlock                      #
#                                                           #
#  Date: 06 OCT 2015                                        #
#  Prerequisites: init.d script for Timesketch              #
#                 fully installed and working elasticsearch,#
#                 timesketch and celery                     #
#############################################################

import os, sys, re, socket, fcntl, struct, subprocess, time

'''
@function log Outputs a string to the terminal at a given level
@param string - string to output to user
@param level - level to output at; 1, 2, -1, -2
'''
def log(s, level):
	DEBUG = True
   	
	if not DEBUG:
    	return

	if level == 1:
		print '[*] %s' %s
	if level == 2:
		print '[**] %s' %s
	if level == -1:
		print '[!] %s' %s
	if level == -2:
		print '[!!] %s' %s
'''
@function psexec Calls psexec.py with given parameters
@param payload - a string specifying the payload for psexec
@param domain - the domain for the target machine
@param user - the user, preferably the admin, to login to the machine with
@param password - the escaped password for the user
@param ip - the ip address of the target machine
'''
def psexec(payload, domain = False, user, password, ip):
	#Base command
	command = 'python /usr/local/bin/psexec.py '
    if domain:
        command += domain+'/'
    command += user + ':' + password + '@' + ip.strip()
    command += ' ' + payload
    log('psexec.py with payload: %s' % payload, 1)
    os.system(command)

'''
@function check_root Checks if script is uid 0 and if not exits
'''
def check_root():
	if os.getuid() != 0:
		print 'THIS SCRIPT MUST RUN AS ROOT'
		sys.exit(1)

'''
@function spopen - Short for subprocess.popen, runs command and returns output
@param command - a string to run as a shell command
@param environ - the environment for the command, defaults to current environment
@return a tuple of (stdout, stderr)
'''
def spopen(command, environ = False):
	environ = environ if environ else os.environ
	p = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True, env = environ)
	out, err = p.communicate()
	return (out, err)

'''
@function service_controls Runs service command with given argument -- basically an alias for spopen
@param service_name - the service name to run a given task against
@param task - the task.  Normally, "start", "stop", "restart"
@return Returns a tuple of (stdout, stderr)
'''
def service_controls(service_name, task='start'):
	command = 'service %s %s' %(service_name, task)
	return spopen(command)

'''
@function get_ip Gets IP for current system, stolen from stackoverflow
@return returns a string of an ipv4 address
'''
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', 'eth0'[:15]))[20:24])

'''
@function start_grr Starts the various services necessary for grr to work
'''
def start_grr():
	#Start elasticsearch and timesketch
	log('Starting elasticsearch...', 2)
    service_controls('elasticsearch')
	log('Starting timesketch...', 2)
    service_controls('timesketch')
    time.sleep(1)

	#Copy current environment, add C_FORCE_ROOT, and pass to spopen
	cur_env = os.environ.copy()
	cur_env['C_FORCE_ROOT'] = "true"
    command = 'celery -A timesketch.lib.tasks worker --loglevel="INFO" &'
	spopen(command, cur_env)

    #os.environ['C_FORCE_ROOT']= "true"
    #os.system('celery -A timesketch.lib.tasks worker --loglevel="INFO" &')
    time.sleep(15)

'''
@function configure_grr Update the Grr config file with user input  and restart GRR
'''
def configure_grr():
	#Get config from grr-server.yaml
	config = ''.join(open('/etc/grr/grr-server.yaml', 'r').readlines())

	#Replace grr comapny name
    client_company_name = raw_input('Enter the client company name >> ').strip()
	config = re.sub( re.compile('Client.company_name\:.*?\n'), 'Client.company_name: %s\n' % client_company_name, config)
    #os.system("sed -i 's/Client\.company_name\:.*/Client\.company_name\: " + client_company_name + "/g' /ect/grr/grr-server.yaml")

    #Replace client name
    client_name = raw_input('Enter the client name >> ').strip()
    #os.system("sed -i 's/Client.name\:.*/Client\.name\: " + client_name + "/g' /etc/grr/grr-server.yaml")
	config = re.sub( re.compile('Client.name\:.*?\n'), 'Client.name: %s\n' % client_name, config)

    #Replace client daemon name
    client_daemon_name = client_name + 'd'
    #os.system("sed -i 's/Client\.binary_name\: ...*/Client\.binary_name\: " + client_daemon_name + "/g' /etc/grr/grr-server.yaml")
	config = re.sub( re.compile('Client.binary_name\: ...*\n'), 'Client.binary_name: %s' % client_daemon_name, config)

    #Run grr updater initialize 
    #Keep all variables if you have already initialized, only change will be rekeying
    #I'll end up adding a logic input here
    #os.system('grr_config_updater initialize')
	spopen('grr_config_updater initialize')

    #Kill all grr_server instances and restart server elements
    #more logic required here for multiple grr_server workers
    ##totally based on quantity of expected hosts - more hosts = more workers
    #os.system('killall grr_server')
    #os.system('sudo /usr/bin/grr_server --start_worker --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
    #os.system('sudo /usr/bin/grr_server --start_ui --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
    #os.system('sudo /usr/bin/grr_server --start_http_server --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
	
	
	spopen('killall grr_server')
	spopen('sudo /usr/bin/grr_server --start_worker --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
	spopen('sudo /usr/bin/grr_server --start_ui --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
	spopen('sudo /usr/bin/grr_server --start_http_server --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')

    return client_name

def nmap():
    existing_results = False 
    #Dirwalk for netsweeper gnmap file
    for dirpath, dirnames, files in os.walk('.'):
        for f in files:
            if 'netsweeper.gnmap' in f:
                print '[!!] There appears to already be scan results...'
                answer = raw_input('[!!] Enter "y" to use those results instead of running a new scan >> ')
                if 'y' in answer.lower():
                    existing_results = True
        if not existing_results:
            #Run the nmap
            print 'Starting nmap...'
            print ''
            nmap_tasking = raw_input('Enter nmap acceptable ip range, CIDR or comma seperated lists >> ')
            
            os.system('nmap -sT -sV -O -Pn -vvv -n ' + nmap_tasking + ' -oA netsweeper &')
            
def windows_recon():
    #check if nmap is currently running
    nmap_done = False
    print ('Verifying nmap completion...', end='')
    while nmap_done != True:
        proc = subprocess.Popen(['ps -ef | grep nmap |  grep -v grep '], stdout=subprocess.PIPE, shell=True)
        (nmap_process, error) = proc.communicate()
        if not 'nmap' in nmap_process.strip():
            nmap_done = True
            print 'Done'
        else:
            print ('.', end='')
        time.sleep(10)
        
    print 'Windows recon...'
    print ''
    os.system('echo `grep -i windows netsweeper.gnmap | \
    grep -i os | \
    grep -Po "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"` >> Windows_hosts.info')

    #Get all the windows IPs
    f = open('Windows_hosts.info', 'r')
    ips = f.readlines()[1].strip().split(' ')
    f.close()

    domain = raw_input('Enter the domain (if no domain esist press enter) >> ')
    if len(domain) < 3:
        domain = False

    user = raw_input('Enter the remote username >> ').strip()
    print 'Enter remote user password [":" and "@" are not allowed]'
    password = raw_input('Remember to \\ escape special characters >> ')
    
    #Run psexec.py against every windows system in serial and get systeminfo command output
    for ip in ips:
        payload = 'systeminfo >> ' + ip.strip() + '.txt'
        psexec(payload, domain, user, password, ip)

    #Create a list of all 64bit Windows systems in file called Win64.list
    command = 'grep -HP "System\sType\:\s+x64" ./*.txt | '
    command += 'awk -F"/" \'{print $2}\' | '
    command += 'awk -F"." \'{print $1"."$2"."$3">"$3}\' >> Win64.list'
    os.system(command)

    #Create a list of all 32bit Windows systems in file called Win32.list
    command = 'grep -HP "System\sType\:\s+X86" ./*.txt | '
    command += 'awk -F"/" \'{print $2}\' | '
    command += 'awk -F"." \'{print $1"."$2"."$3">"$3}\' >> Win32.list'
    os.system(command)

    return (domain, user, password)

def samba(client_name, user, password = '', domain = False):
    print 'Setting up the deployment samba share...'
    print ''
    #Kill any running samba services
    service_controls('nmbd', 'stop')
    service_controls('smbd', 'stop')
    os.system('/etc/init.d/samba stop')
    
    #Add remote user ad samba for automated authentication and grr agent retrieval
    os.system('useradd ' + ' user)
    os.system('smbpasswd -an ' + user)
    os.system('smbpasswd -an ' + user)
    
    #Make the smbtemp folder
    try:
        os.mkdir('/smbtemp')
    except:
        pass
    os.system('chmod 777 /smbtemp')
    os.system(cp /etc/samba/smb.conf /root/')
    os.system('rm -f /etc/samba/smb.conf')
    
    #Build the smb.conf file for our new deployment share
    text = '[global]\n'
    if domain:
        text += '    workgroup = ' + domain + '\n'
    else:
        text += '    workgroup = workgroup' + '\n'
    text += '    netbios name = "SecurityShare' + '\n'
    text += '    wins server = ' + get_ip() + '\n'
    text += '    usershare max = 100000' + '\n'
    text += '    map to guest = Bad User' + '\n'
    text += '    security = user' + '\n'
    text += '[secshare]' + '\n'
    text += '    path = /smbtemp' + '\n'
    text += '    comment = \'Security Share for patch delivery\'' + '\n'
    text += '    writable = yes' + '\n'
    text += '    available = yes' + '\n'
    text += '    browseable = yes' + '\n'
    text += '    guest ok = yes' + '\n'
    text += '    guest only = ok' + '\n'
    text += '    force directory creation mode = 0777' + '\n'
    text += '    force create mode = 0777' + '\n'
    
    f = open('/etc/samba/smb.conf', 'w')
    f.write(text)
    f.close()
    
    #Put your grr agent installers into the smb share and change permissions
    path = '/usr/share/grr/executables/windows/installers/' + client_name + '_3.0.0.7_*'
    os.system('cp ' + path + ' /smbtemp/')
    os.system('chmod -R 777 /smbtemp')
    os.system('chown -R nobody\:nogroup /smbtemp')
    
    #Start the Samba server
    service_controls('nmbd')
    service_controls('smbd')
    os.system('/etc/init.d/samba start')
    
    #Sleep for the share to become available to the hosts
    os.system('sleep 45')
    
def deploy_windows(client_name, domain = False, user, password):
        win64_machines = []
        win32_machines = []
        f = open('Win64.list')
        command = '"\\\\\\SECURITYSHARE\\secshare\\' + client_name + '_3.0.0.7_'
        for machine in f.readlines()[1].strip().split(' '):
            if machine not in win64_machines:
                payload = command + "amd64.exe" >> ' + machine + '.txt'
                psexec(payload, domain, user, password, machine.split())
                win64_machines.append(machine)
        f.close()
        
        for machine in f.readlines()[1].strip().split(' '):
            if machine not in win32_machines:
                payload = command + "i386.exe" >> ' + machine + '.txt'
                psexec(payload, domain, user, password, machine.split())
                win32_machines.append(machine)
        f.close()
        
def revert(user):
    service_controls('nmbd', 'stop')
    service_controls('smbd', 'stop')
    os.system('/etc/init.d/samba', 'stop')
    os.system('cp /usr/share/doc/nautilus-share/examples/smb.conf /etc/samba/smb.conf')
    os.system('rm -rf /smbtemp/*')
    os.system('userdel ' + user)
    
#Check root function call
check_root()

#Nmap network
nmap()

#Start Grr services and processes
start_grr()

#Configure Grr Server
client_name = configure_grr()

#Get windows machines/versioning info
domain, user, password = windows_recon()

#Setup samba share
samba(client_name, user, password, domain)

#Deploy to windows machines (currrently executes in serial due to psexec.py port consumption)
raw_input('Press enter to deploy')
deploy(client_name, domain, user, password)

#Revert Samba share
revert(user)
