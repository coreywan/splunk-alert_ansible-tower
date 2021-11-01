#!/usr/bin/python

import sys, json, os, datetime
import logging, logging.handlers
import splunk.entity as entity
import splunk
import requests

# Tower Connect
#
# This script is used as wrapper to connect to Ansible Tower API.

## Original from:
# __author__ = "Keith Rhea"
# __email__ = "keithr@mindpointgroup.com"
# __version__ = "1.0"

# Refactored By:
__author__ = "Corey Wanless"
__email__ = "corey.wanless@wwt.com"
__version__ = "1.0"

# Setup Logger
def setup_logging():
	logger = logging.getLogger('splunk.tower_api')
	SPLUNK_HOME = os.environ['SPLUNK_HOME']
	LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
	LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
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
	''' Get Tower Credentials from Splunk '''
	myapp = 'splunk-alert_ansible-tower-master'
	try:
		# list all credentials
		entities = entity.getEntities(['admin', 'passwords'], namespace=myapp,
									owner='nobody', sessionKey=sessionKey)
	except Exception as e:
		logger.error("Could not get %s credentials from splunk. Error: %s"
						% (myapp, str(e)))
		raise e

	# return first set of credentials
	for i, c in entities.items():
		if c.get('realm')  == realm:
			return c['username'], c['clear_password']

	logger.error("ERROR: No credentials have been found")

def tower_get_job_launch_link(hostname,username,password,job_name):
	''' Get Job Launch Link from Tower API based on Name '''
	logger.info("Job Name: {}".format(job_name))
	#Attempt to get launch link
	try:
		req = requests.get(
			url = 'https://{}/api/v2/unified_job_templates/?name={}'.format(hostname,job_name),
			headers = {
				"Content-Type": "application/json",
			},
			verify = False,
			auth = (username, password),
		)
		req.raise_for_status()
		results = req.json()
		logger.info("Unified Jobs Found: {}".format(results))
		if results['count'] != 1:
			logger.warn('There was {} templates found with the name of {}'.format(results['count'],job_name))
		launch_link = results['results'][0]['related']['launch']
		logger.info("Launch Link: {}".format(launch_link))
		return launch_link
	except Exception as error:
		logger.error(error)
		raise error

def tower_launch(hostname,username,password,job_name,extra_vars):
	''' Launch Tower Job '''
	launch_link = tower_get_job_launch_link(hostname, username, password, job_name)

	post_data = {
		"url": "https://{}{}".format(hostname,launch_link),
		"headers": {
			"Content-Type": "application/json",
			"Accept": "application/json",
		},
		"verify": False,
		"auth": (username, password),
	}
	if extra_vars != None:
		data = {}
		data['extra_vars'] = json.loads(extra_vars)
		post_data['data'] = json.dumps(data)

	logger.info("Job Post Data: {}".format(post_data))
	#Attempt to Launch Ansible Tower Job Template
	try:
		req = requests.post(**post_data)
		results = req.json()
		logger.info("Job Info: {}".format(results))
		req.raise_for_status()
	except Exception as error:
		logger.error(error)
		raise error

def main(payload):
	#Setup Logger
	global logger

	#Retrieve session key from payload to authenticate to Splunk REST API for secure credential retrieval
	sessionKey = payload.get('session_key')

	#Retrieve Ansible Tower Hostname from Payload configuration
	hostname = payload['configuration'].get('hostname')

	#Retrieve Ansible Tower Job Template ID from Payload configuration
	job_name = payload['configuration'].get('job_name')

	#Retrieve realm  from Payload configuration
	realm = payload['configuration'].get('realm')

	#Retrive Ansible Tower Credentials from Splunk REST API
	username, password = getCredentials(sessionKey,realm)

	#Retrieve Extra Variables from Splunk REST API - Future Add to add Extra Variable Support
	extra_vars = payload['configuration'].get('extra_var')

	#Submit Ansible Tower Job
	tower_launch(hostname,username,password,job_name,extra_vars)

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
		logger.info("Job Completed")
