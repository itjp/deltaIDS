"""
	Delta Intrusion Detection System
		
		A simple IDS, it gets a base system reading, then compares values against it with the check command.
		Best if run with a program such as supervisord

		@author: Dropkick
		@date: 12.4.2013
"""
import os
import subprocess
import sys
import socket
import optparse
import logging
import configparser
import smtplib
import urllib.request
import email
import pwd
import time
import struct

from IPy import IP
from email.mime.text import MIMEText

# Version
version = '0.1'

# Log files
port_log = '.ports'
user_log = '.users'
logm_log = '.logs'
macs_log = '.macs'

machine_ip = str(urllib.request.urlopen('http://www.myexternalip.com/raw').read().decode('utf-8'))

class Scanner(object):

	def __init__(self, host):
		self.host = host
		self.open_port_list = []

	def scan(self, save=False):
		"""Initializes a port scan"""
		logging.info('Checking ports...')
		for port in range(20,10000):
			self.check_port(port)
		if save:
			self.write_to_log()
	
	def check_port(self, port):
		"Scans IP and PORT, appends open ports to OPEN_PORT_LIST"
		try:
			socket.setdefaulttimeout(2)
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((self.host,port))
			sock.close()
			self.open_port_list.append(str(port))
			return
		except IOError as e:
			return

	def write_to_log(self):
		"""Writes results of a port scan to log file"""
		f = open(port_log, 'w')
		for port in self.open_port_list:
			logging.info('[+] Port:'+str(port)+' open.')
			f.write(str(port)+'\n')
		f.close()

	def compare_to_log(self):
		"""Compares port scan to previous port scan (saved in a log file)"""
		self.scan()

		f = open(port_log, 'r')
		previous_open_ports = f.readlines()
		cleaned_previous_open_ports = stripped_log(previous_open_ports)
		f.close()
		
		for port in self.open_port_list:
			if port not in cleaned_previous_open_ports:
				logging.info('[!] '+str(port)+" is now open")
				issue_alert('[!] Port '+str(port)+' is now open.')


class UserMonitor(object):
	
	def __init__(self):
		self.known_user_list = []
	
	def scan(self, save=False):
		logging.info('Checking users...')
		"""Find all users on the system"""
		users = pwd.getpwall()
		for user in users:
			self.known_user_list.append(user.pw_name)
		if save:
			self.write_to_log()

	def write_to_log(self):
		f = open(user_log, 'w')
		for user in self.known_user_list:
			logging.info('[+] Found user: '+user)
			f.write(user+'\n')
		f.close()

	def compare_to_log(self):
		self.scan()

		f = open(user_log, 'r')
		previous_known_users = f.readlines()
		cleaned_previous_known_users = stripped_log(previous_known_users)
		f.close()

		for user in self.known_user_list:
			if user not in cleaned_previous_known_users:
				logging.info('[!] User '+user+' created')
				issue_alert('[!] User '+user+' created')


class LogMonitor(object):

	def __init__(self, auth_log_location='/var/log/auth.log'):
		self.auth_log_location = auth_log_location

	def scan(self, save=False):
		logging.info('Checking logs...')
		self.auth_size = os.path.getsize(self.auth_log_location)
		logging.debug('[+] AUTH size: '+str(self.auth_size))
		if save:
			self.write_to_log()

	def write_to_log(self):
		f = open(logm_log, 'w')
		f.write(str(self.auth_size))
		f.close()

	def compare_to_log(self, threshold):
		self.scan()
		
		f = open(logm_log, 'r')
		previous_auth_size = f.read()
		f.close()

		if(int(previous_auth_size) + threshold < self.auth_size):
			logging.info('[!] Log increased by '+str(self.auth_size - int(previous_auth_size)))
			issue_alert('[!] Log increased by'+str(self.auth_size - int(previous_auth_size)))

class ARPMonitor(object):

	def __init__(self):
		pass

	def get_gateway_ip(self):
		self.gateway_ip = subprocess.check_output("cat /proc/net/route | grep 00000000 | awk '{ print $3 }' | grep -v '00000000'", shell=True)
		self.gateway_ip = IP(struct.unpack('<I', struct.pack('>I', int(self.gateway_ip, 16)))[0])
		logging.debug('[DEBUG] Gateway IP: '+str(self.gateway_ip))

	def scan(self, save=False):
		logging.info('Checking Gateway MAC...')
		self.get_gateway_ip()

		self.gateway_mac = subprocess.check_output("cat /proc/net/arp | grep '"+str(self.gateway_ip)+" ' | awk '{ print $4 }'", shell=True, universal_newlines=True).replace('\n','')
		logging.info('[+] Gateway MAC: '+str(self.gateway_mac))

		if save:
			self.write_to_log()

	def write_to_log(self):
		f = open(macs_log, 'w')
		f.write(str(self.gateway_mac))
		f.close()

	def compare_to_log(self):
		self.scan()
		f = open(macs_log, 'r')
		previous_mac = f.read()
		f.close()
		if str(previous_mac) != str(self.gateway_mac):
			logging.info('[!] Gateway mac address has changed to '+str(self.gateway_mac))
			issue_alert('[!] Gateway mac address has changed to '+str(self.gateway_mac))


class DeltaIDS(object):

	def __init__(self):
		"""Do nothing for now, and oh it does it so well"""
		self.scanner = Scanner('localhost')
		self.user_monitor = UserMonitor()
		self.log_monitor = LogMonitor()
		self.arp_monitor = ARPMonitor()

	def initialize(self):
		"""Get the system base settings"""
		logging.info('Initializing system base state...')

		self.scanner.scan(True)
		self.user_monitor.scan(True)
		self.log_monitor.scan(True)
		self.arp_monitor.scan(True)


	def compare(self):
		"""Run a comparative check against the last recorded state of computer"""
		logging.info('Running a comparative scan...')
		
		self.scanner.compare_to_log()
		self.user_monitor.compare_to_log()
		self.log_monitor.compare_to_log(L_THRESH)
		self.arp_monitor.compare_to_log()


def stripped_log(logfile):
	"""Return a cleaned array from a logfile"""
	cleaned_logfile = []
	for line in logfile:
		cleaned_logfile.append(line.replace('\n',''))
	return cleaned_logfile

def issue_alert(message):
	message = message + '\n\n Originated from '+machine_ip
	alert = email.mime.text.MIMEText(message, _charset='utf-8')
	alert['From'] = "DeltaIDS@localhost.com"
	alert['To'] = R_EMAIL
	alert['Subject'] = email.header.Header("!INTRUSION DETECTED!", 'utf-8')
	
	logging.debug('[DEBUG] Sending email...')
	s = smtplib.SMTP('localhost')
	s.send_message(alert)
	s.quit()

def read_configuration():
	config = configparser.ConfigParser()
	config.read('config.ini')

	R_LOG = config['REPORTING']['logfile']
	logging.basicConfig(filename=str(R_LOG), format='%(asctime)s %(message)s', level=logging.DEBUG)

	global R_EMAIL
	R_EMAIL = config['REPORTING']['email']
	R_EMAIL = R_EMAIL.replace(' ','')
	logging.debug('[DEBUG] ALERT EMAILS: '+str(R_EMAIL))

	global R_FREQUENCY
	R_FREQUENCY = config['REPORTING']['frequency']
	R_FREQUENCY = int(R_FREQUENCY)
	logging.debug('[DEBUG] REPORTING FRQUENCY: '+str(R_FREQUENCY))

	global L_THRESH
	L_THRESH = int(config['REPORTING']['threshold'])

def main():
	read_configuration()
	parser = optparse.OptionParser(version="%prog "+version)

	parser.add_option('-i', '--init', action='store_true', dest='initialize', default=False, help='Write inital values to log files')
	parser.add_option('-c', '--check', action='store_true', dest='check', default=False, help='Check system settings against log files')
	parser.add_option('-v', action='store_true', dest='verbose', default=False, help='verbose mode')

	(options, args) = parser.parse_args()
	
	if(options.verbose):
		root_logger = logging.getLogger()
		c_out = logging.StreamHandler(sys.stdout)
		root_logger.addHandler(c_out)	

	delta = DeltaIDS()
	
	if(options.initialize):
		delta.initialize()
	elif(options.check):
		delta.compare()
	logging.info('...Scan complete')

if __name__ == "__main__":
	main()