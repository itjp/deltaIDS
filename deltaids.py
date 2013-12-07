#! /bin/usr/python

"""
	pyDelta IDS
	@author: Dropkick
	@date: 12.4.2013
"""
import socket
import optparse
import logging
import configparser
import smtplib
import urllib.request
import email

from email.mime.text import MIMEText

version = '0.1'

#Log files
port_log = '.ports'
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
			logging.info('[+] Port '+str(port)+' open.')
			f.write(str(port)+'\n')
		f.close()

	def compare_to_log(self):
		"""Compares port scan to previous port scan (saved in a log file)"""
		self.scan()

		f = open(port_log, 'r')
		previous_open_ports = f.readlines()
		cleaned_previous_open_ports = []
		f.close()
		
		for line in previous_open_ports:
			cleaned_previous_open_ports.append(line.replace('\n',''))

		for port in self.open_port_list:
			if port not in cleaned_previous_open_ports:
				logging.info('[!] '+str(port)+" is now open")
				issue_alert('[!] Port '+str(port)+' is now open.')



class DeltaIDS(object):

	def __init__(self):
		"""Do nothing for now, and oh it does it so well"""
		pass

	def init_port_checker(self):
		"""Get the initially open ports"""
		logging.info('Running an initialzing scan...')
		scanner = Scanner('localhost')
		scanner.scan(True)

	def comp_port_checker(self):
		"""Run a comparative check against the known open ports"""
		logging.info('Running a comparative scan...')
		scanner = Scanner('localhost')
		scanner.compare_to_log()


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
	logging.basicConfig(filename=str(R_LOG), level=logging.DEBUG)

	global R_EMAIL
	R_EMAIL = config['REPORTING']['email']
	R_EMAIL = R_EMAIL.replace(' ','')
	logging.debug('[DEBUG] ALERT EMAILS: '+str(R_EMAIL))


if __name__ == "__main__":
	read_configuration()
	parser = optparse.OptionParser()
	delta = DeltaIDS()

	parser.add_option('-i', '--init', action='store_true', dest='initialize', default=False, help='Write inital values to log files')
	parser.add_option('-c', '--check', action='store_true', dest='check', default=False, help='Check system settings against log files')

	(options, args) = parser.parse_args()
	
	if(options.initialize):
		delta.init_port_checker()
	elif(options.check):
		delta.comp_port_checker()
