#!/usr/bin/python

import sys, urllib, json, tower_cli, os, datetime
import logging, logging.handlers
import splunk.entity as entity
import splunk

# Tower Connect
#
# This script is used as wrapper to connect to Ansible Tower API.

__author__ = "Keith Rhea"
__email__ = "keithr@mindpointgroup.com"
__version__ = "1.0"

# Setup Logger
def setup_logging():
	logger = logging.getLogger('splunk.tower_api')
	SPLUNK_HOME = os.environ['SPLUNK_HOME']
	LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'tower_api.cfg')
	LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'tower_api-local.cfg')
	LOGGING_STANZA_NAME = 'python'
	LOGGING_FILE_NAME = "tower_api.log"
	BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
	LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
	splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a') 
	splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
	logger.addHandler(splunk_log_handler)
	splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
	return logger

#Securely retrieve Ansible Tower Credentials from Splunk REST API password endpoint
def getCredentials(sessionKey,realm):
	myapp = 'alert_ansible_tower'
	try:
		# list all credentials
		entities = entity.getEntities(['admin', 'passwords'], namespace=myapp,
									owner='nobody', sessionKey=sessionKey)
	except Exception as e:
		logger.error("Could not get %s credentials from splunk. Error: %s"
						% (myapp, str(e)))

	# return first set of credentials
	for i, c in entities.items():
		if c.get('realm')  == realm:
			return c['username'], c['clear_password']

	logger.error("ERROR: No credentials have been found")

#Connect to Tower and authenticate using user/pass to receive auth token.
def tower_auth(hostname,username,password):
	try:
		req = urllib.Request(
			url = 'https://' + hostname + '/api/v2/authtoken/',
			headers = {
				"Content-Type": "application/json"
			},
			data = json.dumps({
				"username": username,
				"password": password
			})
		)
		response = urllib.urlopen(req)
		results = json.loads(response.read())
		token = results['token']
		return token
	except urllib.URLError as error:
		logger.error(error.reason)

def tower_launch(hostname,username,password,job_id,extra_vars):
	
	#Authenticate to Ansible Tower and receive Auth Token.
	token = tower_auth(hostname,username,password)
	
	#Attempt to Launch Ansible Tower Job Template
	try:
		req = urllib.Request(
			url = 'https://' + hostname + '/api/v2/job_templates/' + job_id +'/launch/',
			headers = {
				"Content-Type": "application/json",
				"authorization": 'Token ' + token
			},
			data = json.dumps({
				"extra_vars": extra_vars
			})
		)
		response = urllib.urlopen(req)
		results = json.loads(response.read())
		logger.info("Job ID: " + str(results['job']) + " submitted successfully.")
	except urllib.URLError as error:
		logger.error(error.reason)
#Logging Function 
def log(settings):
	f = open(os.path.join(os.environ["SPLUNK_HOME"], "var", "log", "splunk", "tower_api.log"), "a")
	print(str(datetime.datetime.now().isoformat()), settings)
	f.close()


def main(payload):
	#Setup Logger
	global logger
	

	logger.debug('Start of script')
	#Retrieve session key from payload to authenticate to Splunk REST API for secure credential retrieval
	sessionKey = payload.get('session_key')

	#Retrieve Ansible Tower Hostname from Payload configuration
	hostname = payload['configuration'].get('hostname')

	#Retrieve Ansible Tower Job Template ID from Payload configuration
	job_id = payload['configuration'].get('job_id')

	#Retrieve realm  from Payload configuration
	realm = payload['configuration'].get('realm')

	#Retrieve Ansible Tower extra_vars Variable Name from Payload configuration
	var_name = payload['configuration'].get('var_name')

	#Retrieve Ansible Tower extra_vars Field to pull search value from Payload configuration
	var_field = payload['configuration'].get('var_field')

	#Retrieve Ansible Tower extra_vars value from Payload configuration
	var_value = payload['result'].get(var_field)

	#Assign extra_vars variable a value
	extra_vars = str(var_name) + ": " + str(var_value)

	#Retrive Ansible Tower Credentials from Splunk REST API
	username, password = getCredentials(sessionKey,realm)

	#Submit Ansible Tower Job
	tower_launch(hostname,username,password,job_id,extra_vars)



if __name__ == "__main__":
	logger = setup_logging()

	# Check if script initiated with --execute
	if len(sys.argv) < 2 or sys.argv[1] != "--execute":
		#print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
		sys.exit(1)
	else:
		#Get Payload
		payload = json.loads(sys.stdin.read())
		logger.info("Job Started")
		#Pass Pass Payload to main function
		main(payload)
