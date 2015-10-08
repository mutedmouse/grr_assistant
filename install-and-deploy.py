#!/usr/bin/python
#############################################################
#  Created by Frost and Grimlock                            #
#                                                           #
#  Date: 06 OCT 2015                                        #
#  Prerequisites: init.d script for Timesketch              #
#                 fully installed and working elasticsearch,#
#                 timesketch and celery                     #
#############################################################

import os, sys, re, socket, fcntl, struct

def psexec(payload, domain = False, user, password, ip):
    command = 'python /usr/local/bin/psexec.py '
    if domain:
        command += domain+'/'
    command += user + ':' + password + '@' + ip.strip()
    command += ' ' + payload
    print command
    os.system(command)

#def check_root():
#   uid = os.getuid()
#   if uid = "0":
#       print 'Executing as root'
#   else:
#        print 'Please run as root user'
#        sys.exit(1)

def service_controls(service_name, task='start'):
    os.system('service ' + service_name + ' ' + task

def get_ip():
    #TAKEN FROM STACKOVERFLOW.COM
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
    0x8915,
    struct.pack('256s', 'eth0'[:15]))[20:24])

def start_grr():
    service_controls('elasticsearch')
    service_controls('timesketch')
    os.system('sleep 1')
    os.environ['C_FORCE_ROOT']= "true"
    os.system('celery -A timesketch.lib.tasks worker --loglevel="INFO" &')
    os.system('sleep 15')

def configure_grr():
    #Replace grr comapny name
    client_company_name = raw_input('Enter the client company name >> ').strip()
    os.system("sed -i 's/Client\.company_name\:.*/Client\.company_name\: " + client_company_name + "/g' /ect/grr/grr-server.yaml")

    #Replace client name
    client_name = raw_input('Enter the client name >> ').strip()

    os.system("sed -i 's/Client.name\:.*/Client\.name\: " + client_name + "/g' /etc/grr/grr-server.yaml")

    #Replace client daemon name
    client_daemon_name = client_name + 'd'
    os.system("sed -i 's/Client\.binary_name\: ...*/Client\.binary_name\: " + client_daemon_name + "/g' /etc/grr/grr-server.yaml")

    #Run grr updater initialize 
    #Keep all variables if you have already initialized, only change will be rekeying
    #I'll end up adding a logic input here
    os.system('grr_config_updater initialize')

    #Kill all grr_server instances and restart server elements
    #more logic required here for multiple grr_server workers
    ##totally based on quantity of expected hosts - more hosts = more workers
    os.system('killall grr_server')
    os.system('sudo /usr/bin/grr_server --start_worker --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
    os.system('sudo /usr/bin/grr_server --start_ui --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')
    os.system('sudo /usr/bin/grr_server --start_http_server --disallow_missing_config_definitions --config=/etc/grr/grr-server.yaml &')

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
            os.system('nmap -sT -sV -O -Pn -vvv -n ' + nmap_tasking + ' -oA netsweeper')
            
def windows_recon():
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

#Start Grr services and processes
start_grr()

#Configure Grr Server
client_name = configure_grr()

#Nmap network
nmap()

#Get windows machines/versioning info
domain, user, password = windows_recon()

#Setup samba share
samba(client_name, user, password, domain)

#Deploy to windows machines (currrently executes in serial due to psexec.py port consumption)
raw_input('Press enter to deploy')
deploy(client_name, domain, user, password)

#Revert Samba share
revert(user)
