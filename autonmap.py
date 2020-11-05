import os, subprocess
os.system("sudo apt-get install nmap >/dev/null 2>&1")
os.system("pip install --upgrade python-nmap >/dev/null 2>&1")
os.system("sudo apt-get install nikto >/dev/null 2>&1")
import optparse,nmap
#initialize the port scanner
import json, datetime
import argparse

def callbackMySql(host, result):
        try:
                script = result['scan'][host]['tcp'][3306]['script']
                
                print("Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass

def callbackFTP(host, result):
        try:
                script = result['scan'][host]['tcp'][21]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))
                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        
def callbackVNC(host, result):
        try:
                script = result['scan'][host]['tcp'][5900]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        
def callbackNFS(host, result):
        try:
                script = result['scan'][host]['tcp'][111]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        

        
def callbackMySql(host, result):
        try:
                script = result['scan'][host]['tcp'][3306]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        
def callbackSSL(host, result):
        try:
                script = result['scan'][host]['tcp'][443]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        
def callbackSSH(host, result):
        try:
                script = result['scan'][host]['tcp'][22]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass
        
def callbackHTTP(host, result):
        try:
                script = result['scan'][host]['tcp'][80]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass

def callbackPOP3(host, result):
        try:
                script = result['scan'][host]['tcp'][110]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        
'''
def callbackWINDOWS(host, result):
        try:
                script = result['scan'][host]['tcp'][888]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        
'''

def callbackSNMP(host, result):
        try:
                script = result['scan'][host]['tcp'][161]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        

def callbackSMTP(host, result):
        try:
                script = result['scan'][host]['tcp'][25]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        

def callbackWINDOWS(host, result):
        try:
                script = result['scan'][host]['tcp'][445]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        

'''
def callback*(host, result):
        try:
                script = result['scan'][host]['tcp'][888]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        
'''
'''
def callback*(host, result):
        try:
                script = result['scan'][host]['tcp'][888]['script']
                
                print( "Command line"+ result['nmap']['command_line'])
                f.write(str("Command line"+ result['nmap']['command_line']))

                for key, value in script.items():
                        print( 'Script {0} --> {1}'.format(key, value))
                        f.write(str('Script {0} --> {1}'.format(key, value)))
        except KeyError:
                # Key is not present
                pass        
'''

class NmapScannerAsync:
        
        def __init__(self):
                self.nmsync = nmap.PortScanner()
                self.nmasync = nmap.PortScannerAsync()
    
        def scanning(self):
                while self.nmasync.still_scanning():
                        self.nmasync.wait(5)    

        def nmapScan(self, hostname, port):
                try:
                        print( "Checking port "+ port +" ..........")
                        
                        self.nmsync.scan(hostname, port)
                
                        self.state = self.nmsync[hostname]['tcp'][int(port)]['state']
                        print( " [+] "+ hostname + " tcp/" + port + " " + self.state ) 
                        f.write(str(" [+] "+ hostname + " tcp/" + port + " " + self.state ))                          

                        #mysql
                        if (port=='3306') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking MYSQL port with nmap scripts......')
                                
                                #scripts for mysql:3306 open
                                print( 'Checking mysql-audit.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-audit.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-brute.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-databases.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-databases.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-databases.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-dump-hashes.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-dump-hashes.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-empty-password.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-enum.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-enum.nse",callback=callbackMySql)
                                self.scanning()
                                print( 'Checking mysql-info.nse".....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-info.nse",callback=callbackMySql) 
                                self.scanning()
                                print( 'Checking mysql-query.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-query.nse",callback=callbackMySql)  
                                self.scanning()
                                print( 'Checking mysql-users.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-users.nse",callback=callbackMySql)  
                                self.scanning()
                                print( 'Checking mysql-variables.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-variables.nse",callback=callbackMySql) 
                                self.scanning()
                                print( 'Checking mysql-vuln-cve2012-2122.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p3306 --script mysql-vuln-cve2012-2122.nse",callback=callbackMySql) 
                                self.scanning()
                                
                        #FTP
                        if (port=='21') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking ftp port with nmap scripts......')
                                #scripts for ftp:21 open
                                print( 'Checking ftp-anon.nse .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-anon.nse",callback=callbackFTP)
                                self.scanning()
                                print( 'Checking ftp-bounce.nse  .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-bounce.nse",callback=callbackFTP)
                                self.scanning()
                                print( 'Checking banner.nse  .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script banner.nse",callback=callbackFTP)
                                self.scanning()
                                print( 'Checking ftp-libopie.nse  .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-libopie.nse",callback=callbackFTP)
                                self.scanning()
                                print( 'Checking ftp-proftpd-backdoor.nse  .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-proftpd-backdoor.nse",callback=callbackFTP)
                                self.scanning()
                                print( 'Checking ftp-vsftpd-backdoor.nse   .....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p21 --script ftp-vsftpd-backdoor.nse",callback=callbackFTP)
                                self.scanning()
                
                        #vnc
                        if (port=='5900') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking VNC port with nmap scripts......')
                                #scripts for vnc:5900 open
                                print( 'Checking vnc-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p5900 --script vnc-brute.nse",callback=callbackVNC)
                                self.scanning()
                                print( 'Checking vnc-info.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p5900 --script vnc-info.nse",callback=callbackVNC)
                                self.scanning()
                        #pop3
                        if (port=='110') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking POP3 port with nmap scripts......')
                                #scripts for vnc:5900 open
                                print( 'Checking pop3-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p110 --script pop3-brute.nse",callback=callbackPOP3)
                                self.scanning()
                                print( 'Checking pop3-ntlm-info.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p110 --script pop3-ntlm-info.nse",callback=callbackPOP3)
                                self.scanning()
                                print( 'Checking pop3-capabilities.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p110 --script pop3-capabilities.nse",callback=callbackPOP3)
                                self.scanning()

                        #nfs
                        if (port=='111') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking NFS port with nmap scripts......')
                                #scripts for NFS:5432 open
                                print( 'Checking nfs-ls.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p111 --script nfs-ls.nse",callback=callbackNFS)
                                self.scanning()
                                print( 'Checking nfs-showmount.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p111 --script nfs-showmount.nse",callback=callbackNFS)
                                self.scanning()
                                print( 'Checking nfs-statfs.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p111 --script nfs-statfs.nse",callback=callbackNFS)
                                self.scanning()
                                print( 'Checking rpcinfo.....')
                                self.nmasync.scan(hostname,arguments="-A -sV --script rpcinfo.nse",callback=callbackNFS)
                                self.scanning()
                        
                        #ssl
                        if (port=='443') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking SSL port with nmap scripts......')
                                #scripts for ssl:443 open
                                print( 'Checking ssl-cert.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script ssl-cert.nse",callback=callbackSSL)
                                self.scanning()
                                print( 'Checking ssl-date.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script ssl-date.nse",callback=callbackSSL)
                                self.scanning()
                                print( 'Checking ssl-enum-ciphers.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script ssl-enum-ciphers.nse",callback=callbackSSL)
                                self.scanning()
                                print( 'Checking ssl-google-cert-catalog.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script ssl-google-cert-catalog.nse",callback=callbackSSL)
                                self.scanning()
                                print( 'Checking ssl-known-key.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script ssl-known-key.nse",callback=callbackSSL)
                                self.scanning()
                                print( 'Checking sslv2.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p443 --script sslv2.nse",callback=callbackSSL)
                                self.scanning()
                                
                        #ssh
                        if (port=='22') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking SSH port with nmap scripts......')
                                #scripts for SSH:22 open)
                                print( 'Checking rsa-vuln-roca.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p22 --script rsa-vuln-roca.nse",callback=callbackSSH)
                                self.scanning()
                                print( 'Checking ssh2-enum-algos.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p22 --script ssh2-enum-algos.nse",callback=callbackSSH)
                                self.scanning()
                                print( 'Checking sshv1.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p22 --script sshv1.nse",callback=callbackSSH)
                                self.scanning()
                                
                        #http
                        if (port=='80' or port=='8080') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking HTTP port with nmap scripts......')
                                #scripts for http:80 open
                                print( 'Checking http-enum.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-enum.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking dns-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script dns-brute.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-adobe-coldfusion-apsa1301.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-adobe-coldfusion-apsa1301.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-apache-negotiation.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sS -p80 --script http-apache-negotiation.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-drupal-enum.nse....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-drupal-enum.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-phpmyadmin-dir-traversal.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-phpmyadmin-dir-traversal.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-proxy-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-proxy-brute.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-sql-injection.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-sql-injection.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-wordpress-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-wordpress-brute.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-wordpress-enum.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-wordpress-enum.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-wordpress-plugins.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-wordpress-plugins.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-coldfusion-subzero.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-coldfusion-subzero.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-drupal-enum-users.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-drupal-enum-users.nse",callback=callbackHTTP)
                                self.scanning()
                                print( 'Checking http-drupal-modules.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p80 --script http-drupal-modules.nse",callback=callbackHTTP)
                                self.scanning()

                         #snmp
                                  
                        if (port=='161') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking SNMP port with nmap scripts......')
                                #scripts for ----:161 open)
                                print( 'Checking snmp-info.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-info.nse",callback=callbackSNMP)
                                self.scanning()
                                print( 'Checking snmp-interfaces.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-interfaces.nse",callback=callbackSNMP)
                                self.scanning()
                                print( 'Checking snmp-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-brute.nse",callback=callbackSNMP)
                                self.scanning()
                                print( 'Checking snmp-processes.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-processes.nse",callback=callbackSNMP)
                                self.scanning()
                                print( 'Checking snmp-sysdescr.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-sysdescr.nse",callback=callbackSNMP)
                                self.scanning()
                                print( 'Checking snmp-netstat.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p161 --script snmp-netstat.nse",callback=callbackSNMP)
                                self.scanning()
                        
                        
           
                        #stmp
                        
                        if (port=='25') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking ---- port with nmap scripts......')
                                #scripts for ----:888 open)
                                print( 'Checking enum-users.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p25 --script enum-users.nse",callback=callbackSMTP)
                                self.scanning()
                                print( 'Checking stmp-open-relay.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p25 --script stmp-open-relay.nse",callback=callbackSMTP)
                                self.scanning()
                                print( 'Checking stmp-brute.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p25 --script stmp-brute.nse",callback=callbackSMTP)
                                self.scanning()
                                print( 'Checking stmp-strangeport.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p25 --script stmp-strangeport.nse",callback=callbackSMTP)
                                self.scanning()
                                print( 'Checking stmp-ntlm-info.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p25 --script stmp-ntlm-info.nse",callback=callbackSMTP)
                                self.scanning()
                        
                        
           
                        #windows
                         
                        if (port=='445') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking ---- port with nmap scripts......')
                                #scripts for ----:888 open)
                                print( 'Checking msrpc-enum.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script msrpc-enum.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-domains.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-domains.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-groups.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-groups.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-processes.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-processes.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-sessions.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-sessions.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-shares.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-shares.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-enum-users.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-users.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-mbenum.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-enum-users.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-os-discovery.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-os-discovery.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-security-mode.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-security-mode.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-server-stats.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-server-stats.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smb-system-info.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smb-system-info.nse",callback=callbackWINDOWS)
                                self.scanning()
                                print( 'Checking smbv2-enabled.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p445 --script smbv2-enabled.nse",callback=callbackWINDOWS)
                                self.scanning()

                        '''
                        if (port=='888') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking ---- port with nmap scripts......')
                                #scripts for ----:888 open)
                                print( 'Checking *.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p888 --script *.nse",callback=callback*)
                                self.scanning()
                        '''

                        '''
                        if (port=='888') and self.nmsync[hostname]['tcp'][int(port)]['state']=='open':
                                print( 'Checking ---- port with nmap scripts......')
                                #scripts for ----:888 open)
                                print( 'Checking *.nse.....')
                                self.nmasync.scan(hostname,arguments="-A -sV -p888 --script *.nse",callback=callback*)
                                self.scanning()
                        '''
         
            
                except Exception as e:
                        print( str(e))
                        print( "Error to connect with " + hostname + " for port scanning" )
                        pass
        

scanner = nmap.PortScanner()

print("Welcome to EnumHunter")
print("<--------------------------->")
x=input("Enter number of IP's you want to scan:")
y=1
ip_list = []
while int(x)>=y:
        ip = input("Please enter the "+str(y)+" IP address you want to scan:")
        ip_list.append(ip)
        y=y+1
print(ip_list)
z=1
for ips in ip_list:
        ip_addr = ips 
        #input the IP address you want scanned
        print("The "+str(z)+" IP you entered is: ", ip_addr)
        type(ip_addr)
        directory = os.getcwd()
        directory = str(directory + '/' + ip_addr)
        if os.path.isdir(directory):
                pass
        else:
                os.system("sudo mkdir "+str(ip_addr)+" >/dev/null 2>&1")

        resp = input("""\nPlease enter the type of scan you want to run
                        1)SYN ACK Scan
                        2)UDP Scan
                        3)Comprehensive Scan
                        4)FTP
                        5)SSH
                        6)NFS
                        7)MYSQL
                        8)VNC
                        9)SSL
                        10)HTTP
                        11)POP3
                        12)Nikto
                        13)SNMP
                        14)SMTP
                        15)WINDOWS
                        16)All\n""")
        print("You have selected option: ", resp)
        if resp != '16':
                directory = str(directory+'/'+resp+'.txt')
                f = open(str(directory), "a")
                f.write(str("------------------"+'\n'+str(datetime.datetime.now())+"-----------------------------"+'\n'))
        if resp == '1':
            f.write(str("-----------------SYN ACK Scan--------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(str(ip_addr), '1-100', '-v -sS')
            scanner.command_line()
            print(scanner.scaninfo())
            f.write(str(scanner.scaninfo()))
            ports=scanner[ip_addr]['tcp'].keys()
            for port in ports:
                print("Port :",port,"\tService Name: ",scanner[ip_addr]['tcp'][int(port)]['name'])
                f.write("".join(["Port :",str(port),"\tService Name: ",str(scanner[ip_addr]['tcp'][int(port)]['name'])]))
                #print(str(+str('\t')+str(str(scanner[ip_addr]['tcp'][int(value)]['name']))))
        elif resp == '2':
            f.write(str("----------------UDP Scan--------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(str(ip_addr), '1-100', '-v -sU')
            scanner.command_line()
            print(scanner.scaninfo())
            f.write(str(scanner.scaninfo()))
            print("Ip Status: ", scanner[ip_addr].state())
            ports=scanner[ip_addr]['udp'].keys()
            for port in ports:
                print("Port :",port,"\tService Name: ",scanner[ip_addr]['udp'][int(port)]['name'])
                f.write("".join(["Port :",str(port),"\tService Name: ",str(scanner[ip_addr]['udp'][int(port)]['name'])]))
        elif resp == '3':
            f.write(str("------------------Comprehensive Scan----------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            data = os.popen("sudo nmap -p 1-1024 -T4 -A -v "+ip_addr).read()
            print(data)
            f.write(str(data))
        elif resp == '4':
            f.write(str("------------------------FTP-------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(21))
            
        elif resp == '5':
            f.write(str("-----------------------SSH---------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(22))
            
        elif resp == '6':
            f.write(str("-------------------------NFS------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(111))
            
        elif resp == '7':
            f.write(str('------------------------------MYSQL-----------------'+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(3306))
            
        elif resp == '8':
            f.write(str("----------------VNC-----------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(5900))
            
        elif resp == '9':
            f.write(str("-----------------------------SSL-----------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(443))
            
        elif resp == '10':
            f.write(str("---------------------HTTP-------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(80))

        elif resp == '11':
            f.write(str("---------------------------POP3------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(110))

        elif resp == '12':
            f.write(str("---------------------------Nikto------------------"+'\n'))
            cmd=str('cd /home/username/Desktop && sudo nikto -host '+ ip_addr)
            data1 = os.popen(cmd).read()
            print(data1)
            f.write(str(data1))

        elif resp == '13':
            f.write(str("---------------------------SNMP------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(161))

        elif resp == '14':
            f.write(str("---------------------------SMTP------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            NmapScannerAsync().nmapScan(str(ip_addr), str(25))

        elif resp == '15':
             f.write(str("---------------------------Windows------------------"+'\n'))
             print("Nmap Version: ", scanner.nmap_version())
             NmapScannerAsync().nmapScan(str(ip_addr), str(445))

        elif resp == '16':
            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/Comprehensive'+'.txt')
            f = open(str(directory), "a")
            f.write(str("------------------Comprehensive Scan----------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            data2 = os.popen("sudo nmap -p 1-1024 -T4 -A -v "+ip_addr).read()
            print(data2)
            f.write(str(data2))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/Nikto'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------------Nikto------------------"+'\n'))
            cmd=str('cd /home/username/Desktop && sudo nikto -host '+ ip_addr)
            data3 = os.popen(cmd).read()
            print(data3)
            f.write(str(data3))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/FTP'+'.txt')
            f = open(str(directory), "a")
            f.write(str("------------------------FTP-------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(21))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/SSH'+'.txt')
            f = open(str(directory), "a")
            f.write(str("-----------------------SSH---------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(22))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/NFS'+'.txt')
            f = open(str(directory), "a")
            f.write(str("-------------------------NFS------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(111))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/MYSQL'+'.txt')
            f = open(str(directory), "a")
            f.write(str('------------------------------MYSQL-----------------'+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(3306))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/MYSQL'+'.txt')
            f = open(str(directory), "a")
            f.write(str("----------------VNC-----------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(5900))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/SSL'+'.txt')
            f = open(str(directory), "a")
            f.write(str("-----------------------------SSL-----------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(443))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/HTTP'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------HTTP-------------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(80))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/POP3'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------------POP3------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(110))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/SNMP'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------------SNMP------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(161))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory+'/SMTP'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------------SMTP------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(25,465,587))))
            f.write(str("------------------------END-----------------------------------"+'\n'))
            f.close()

            directory = os.getcwd()
            directory = str(directory + '/' + ip_addr)
            directory = str(directory+'/Windows'+'.txt')
            f = open(str(directory), "a")
            f.write(str("---------------------------Windows------------------"+'\n'))
            print("Nmap Version: ", scanner.nmap_version())
            f.write(str(NmapScannerAsync().nmapScan(str(ip_addr), str(445))))
            f.write(str("------------------------END-----------------------------------"+'\n'))

        elif resp > '16' or resp <= '0':
            print("Please enter a valid option")

        f.write(str("------------------------END-----------------------------------"+'\n'))
        f.close()
        z=z+1
