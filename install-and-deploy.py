#!/usr/bin/python
'''
  Created by frosty_1313 and Grimlock
  Date: 06 OCT 2015
  Prerequisites:
				- init.d script for Timesketch
                - installed and working elasticsearch,
				  timesketch and celery                     
				- python-nmap (xael.org/pages/python-nmap-X.X.X.tar.gz)
'''
#Normal python libraries
import os, sys, re, socket, fcntl, struct, subprocess, time, tempfile, pprint, ast
#Custom installs
import nmap

DEBUG = True
'''
@function log Outputs a string to the terminal at a given level
@param s - string to output to user
@param level - level to output at; 1, 2, -1, -2
'''
def log(s, level):
	if level == 1:
		print '[*] %s' %s
	if level == 2:
		print '[**] %s' %s
	if level == -1:
		print '[!] %s' %s
	if level == -2:
		print '[!!] %s' %s

'''
@function debug Output string if global DEBUG is true
@param s - string to output
'''
def debug(s):
	global DEBUG
	if DEBUG:
		print '[DEBUG] %s' % s

'''
@function psexec Calls psexec.py with given parameters
@param payload - a string specifying the payload for psexec
@param user - the user, preferably the admin, to login to the machine with
@param password - the escaped password for the user
@param ip - the ip address of the target machine
@param domain - the domain for the target machine
'''
def psexec(payload, user, password, ip, domain = False):
	#Base command
	command = 'python /usr/local/bin/psexec.py '
	if domain:
		command += domain+'/'
	command += user + ':' + password + '@' + ip.strip()
	command += ' ' + payload
	log('psexec.py with payload: %s' % payload, 1)
	debug(command)
	spopen(command)

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
def spopen(command, environ = os.environ):
	#Use tempfiles because Pipe can become full
	tempout = tempfile.TemporaryFile()
	temperr = tempfile.TemporaryFile()

	p = subprocess.Popen(command, stdout = tempout, stderr = temperr, env = environ)
	#Wait for process to complete
	p.wait()

	#Return to beginning of files
	tempout.seek(0)
	temperr.seek(0)

	#Join data
	out = ''.join( tempout.readlines() )
	err = ''.join( temperr.readlines() )


	debug('Command: %s\n\tSTDOUT: %s\n\tSTDERR: %s' % (command, out, err))
	return (out, err)

'''
@function service_controls Runs service command with given argument -- basically an alias for spopen
@param service_name - the service name to run a given task against
@param task - the task.  Normally, "start", "stop", "restart"
@return Returns a tuple of (stdout, stderr)
'''
def service_controls(service_name, task='start'):
	command = ['service', service_name, task]
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

	#Copy current environment, add C_FORCE_ROOT, and pass to popen
	#Need to wait for output
	log('Starting celery...', 2)
	new_env = os.environ.copy()
	new_env['C_FORCE_ROOT'] = "true"
	command = ['celery', '-A', 'timesketch.lib.tasks', 'worker', '--loglevel=INFO']
	#Use f as a tempfile to get output back
	with tempfile.TemporaryFile() as f:
		subprocess.Popen(command, stdout = f, stderr = f, env = new_env)
		time.sleep(5)
		f.seek(0)
		debug(''.join( f.readlines() ))
	
	time.sleep(10)

'''
@function configure_grr Update the Grr config file with user input  and restart GRR
'''
def configure_grr():
	#Get config from grr-server.yaml
	config = ''.join(open('/etc/grr/grr-server.yaml', 'r').readlines())

	#Replace grr comapny name
	client_company_name = raw_input('Enter the client company name >> ').strip()
	config = re.sub( re.compile('Client.company_name\:.*?\n'), 'Client.company_name: %s\n' % client_company_name, config)

    #Replace client name
	client_name = raw_input('Enter the client name >> ').strip()
	config = re.sub( re.compile('Client.name\:.*?\n'), 'Client.name: %s\n' % client_name, config)

    #Replace client daemon name
	client_daemon_name = client_name + 'd'
	config = re.sub( re.compile('Client.binary_name\: ...*\n'), 'Client.binary_name: %s' % client_daemon_name, config)
	
	#Write the config file
	f =open('/etc/grr/grr-server.yaml', 'w')
	f.write(config)
	f.close()

    #Run grr updater initialize 
    #Keep all variables if you have already initialized, only change will be rekeying
    #TODO: add a logic input here
	spopen(['grr_config_updater', 'initialize'])

    #Kill all grr_server instances and restart server elements
    #more logic required here for multiple grr_server workers
    ##totally based on quantity of expected hosts - more hosts = more workers
	#Use normal subprocess.Popen, there is no output from these
	log('Attempting to kill already existing grr_server processes', 2)
	spopen(['killall', 'grr_server'])

	log('Restarting grr_server', 1)
	subprocess.Popen(['/usr/bin/grr_server', '--start_worker', '--disallow_missing_config_definitions', '--config=/etc/grr/grr-server.yaml'])
	subprocess.Popen(['/usr/bin/grr_server', '--start_ui', '--disallow_missing_config_definitions', '--config=/etc/grr/grr-server.yaml'])
	subprocess.Popen(['/usr/bin/grr_server', '--start_http_server', '--disallow_missing_config_definitions', '--config=/etc/grr/grr-server.yaml'])

	return client_name

'''
@function nmap_network Scan a user provided network segment for hosts, also checks if scan results already exists and if user wants to resuse those
@return returns a dictionary of hosts with ip as key and a dict of host data as
	the values.  Each host dictionary will have the following keys: hostname, 
	vendor, mac, ipv4, ipv6, ports(a dictionary of port details), os_vendor,
	os_family, os_type and os_vers.  This is also output to scan_results.json
'''
#TODO: Allow user to keep results and add to them
#TODO: Break scanning out into its own class
def nmap_network():
	#Check if results exist
	results_exist = 0
	if os.path.isfile('scan_results.json'):
		log('''There appears to be scan results already.  Would you like to:
	(1) Reuse these results without scanning again[default]
	(2) Discard those results and start over?''', 2)
		results_exist = raw_input(' >> ').strip() or 1
		results_exist = int(results_exist)
	
	#If we are going to resuse results, reload scan_results.json
	if results_exist == 1:
		results = ''.join(open('scan_results.json', 'r').readlines())
		#ast.literal_eval evaluates a string to a built in python type
		#In this case, a dictionary
		return ast.literal_eval(results)

	#Get network to scan
	nmap_tasking = raw_input('Enter nmap acceptable network or host information >> ').strip()
	#Initialize scanner and conduct scan
	scanner = nmap.PortScanner()
	log('Running nmap against %s' % nmap_tasking, 1)
	debug('nmap %s -sT -sV -A -Pn -n -p0-1024' % nmap_tasking)
	scanner.scan(hosts = nmap_tasking, arguments = '-sT -sV -A -Pn -n -p0-1024')	

	#Dictionary that will eventually be scanned
	ret_dict = {}
	
	for host in scanner.all_hosts():
		#Assign a temporary value to hold this host's results
		temp = scanner[host]
		#If the host is in fact up
		if temp.state() == 'up':
			#Using .get() method allows for error recovery if key is not present
			new_host = {}
			new_host['hostname'] = temp.hostname()
			
			#[vendor] is a dict of mac: vendor, we want the first value
			#if this doesn't exist, assign none
			vend = temp.get('vendor', None)
			new_host['vendor'] = vend.values()[0] if vend else None

			#Get various addresses
			addresses = temp.get('addresses', {})
			new_host['mac'] = addresses.get('mac', None)
			new_host['ipv4'] = addresses.get('ipv4', None)
			new_host['ipv6'] = addresses.get('ipv6', None)
			new_host['ports'] = []

			#Get TCP and UDP ports
			for protocol in ['tcp', 'udp']:
				#Iterate through the ports for each protocol
				for port in temp.get(protocol, {}).keys():
					new_port = {}
					new_port['num'] = port
					new_port['type'] = protocol

					#Get the port details from results
					temp_port = temp.get('tcp', {}).get(port, {})
					new_port['product'] = temp_port.get('product', None)
					new_port['name'] = temp_port.get('name', None)
					new_port['state'] = temp_port.get('state', None)

					new_host['ports'].append(new_port)

			#Get OS information
			osclass = temp.get('osclass', {})
			new_host['os_vendor'] = osclass.get('vendor')
			new_host['os_family'] = osclass.get('osfamily')
			new_host['os_type'] = osclass.get('type')
			new_host['os_vers'] = osclass.get('osgen')

			ret_dict[host] = new_host

			#Format for debugging sanity
			pp = pprint.PrettyPrinter(indent = 3)
			debug('Found: %s' % pp.pformat(new_host))

	#Save results to scan_results.json
	pp = pprint.PrettyPrinter(indent = 1)
	f = open('scan_results.json', 'w')
	f.write( pp.pformat(ret_dict) )
	f.close()
	
	return ret_dict

def windows_recon():
    #check if nmap is currently running
    nmap_done = False
    #print ('Verifying nmap completion...', end='')
    while nmap_done != True:
        proc = subprocess.Popen(['ps -ef | grep nmap |  grep -v grep '], stdout=subprocess.PIPE, shell=True)
        (nmap_process, error) = proc.communicate()
        if not 'nmap' in nmap_process.strip():
            nmap_done = True
            print 'Done'
        else:
            #print ('.', end='')
			pass
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
    os.system('useradd ' + user)
    os.system('smbpasswd -an ' + user)
    os.system('smbpasswd -an ' + user)
    
    #Make the smbtemp folder
    try:
        os.mkdir('/smbtemp')
    except:
        pass
    os.system('chmod 777 /smbtemp')
    os.system('cp /etc/samba/smb.conf /root/')
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
    
def deploy_windows(client_name, user, password, domain = False):
        win64_machines = []
        win32_machines = []
        f = open('Win64.list')
        command = '"\\\\\\SECURITYSHARE\\secshare\\' + client_name + '_3.0.0.7_'
        for machine in f.readlines()[1].strip().split(' '):
            if machine not in win64_machines:
                payload = command + 'amd64.exe >> ' + machine + '.txt'
                psexec(payload, domain, user, password, machine.split())
                win64_machines.append(machine)
        f.close()
        
        for machine in f.readlines()[1].strip().split(' '):
            if machine not in win32_machines:
                payload = command + 'i386.exe >> ' + machine + '.txt'
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
scan_results = nmap_network()

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
