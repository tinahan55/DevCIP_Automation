import platform
import os
import logging


class Network(object):
    def __init__(self,logname=""):
        self.logname = logname
        self.logger = logging.getLogger('%s.Network_Tool'%(self.logname))
        self.logger.info('creating the sub log for Network_Tool')

    def Host_Ping(self,hostname,times):
        checkstring ='Reply from %s'%(hostname)
        if platform.system() == "Windows":
            response = os.system("ping %s -n %s"%(hostname,times))
        else:
            response = os.system("ping -c%s %s "%(times,hostname))
        isUpBool = False
        if response ==0:
            isUpBool = True
        return isUpBool

import logging
from time import gmtime, strftime
class Log(object):
    def __init__(self,log_file_name,log_name):
        self.logfilename = "%s%s.log"%(log_file_name,strftime("%Y%m%d%H%M", gmtime()))
        self.logname = log_name
        self.logger = self.__set_log()


    def __set_log(self):
        logpath = os.path.join(os.getcwd(), 'log')
        if not os.path.exists(logpath):
            os.makedirs(logpath)
        filepath = os.path.join(logpath, self.logfilename)
        logger = logging.getLogger(self.logname)
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh = logging.FileHandler(filepath)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        logger.addHandler(console)
        return logger


    def write(self,type,log_text):
        if type =="info":
            self.logger.info(log_text)
        elif type =="debug":
            self.logger.debug(log_text)
        elif type =="error":
            self.logger.error(log_text)

    def info(self,log_text):
        self.logger.info(log_text)


    def debug(self,log_text):
        self.logger.debug(log_text)

    def error(self,log_text):
        self.logger.error(log_text)

import urllib2,urllib, json, base64
class APIClient:
    def __init__(self,base_url):
        if not base_url.endswith('/'):
            base_url += '/'
        self.__url = base_url

    def send_get(self, uri,data):
        url_values = urllib.urlencode(data)
        uri = uri+ "?"+ url_values
        return self.__send_request('GET', uri, None)

	def send_post(self, uri, data):
		return self.__send_request('POST', uri, data)


    def __send_request(self, method, uri, data):
		url = self.__url + uri
		request = urllib2.Request(url)
		if (method == 'POST'):
			request.add_data(json.dumps(data))

		e = None
		try:
			response = urllib2.urlopen(request).read()
		except urllib2.HTTPError as e:
			response = e.read()

		if response:
			result = json.loads(response)
		else:
			result = {}

		if e != None:
			if result and 'error' in result:
				error = '"' + result['error'] + '"'
			else:
				error = 'No additional error message received'
			raise APIError('TestRail API returned HTTP %s (%s)' %
				(e.code, error))

		return result

class APIError(Exception):
	pass

from collections import OrderedDict

class PassProfileJson:
    def __init__(self):
        self.key = ""
        self.keyvalue=""


    def remove_parsing_failstring(self,content):
        result =  json.loads(content.replace('"','\\"').replace("u'","'").replace("'","\""))
        return result


    def get_value_by_key(self,content,keyname):
        keyvalue =''
        for key, value in dict.items(self.remove_parsing_failstring(content)):
            if key ==  keyname:
                keyvalue = value
        return keyvalue

    def get_configlist_by_key(self,content,keyname):

        configlist =  list()
        keyvalue =''
        for key, value in dict.items(self.remove_parsing_failstring(content)):
            if key ==  keyname:
                configlist = value.split("\n")
        return configlist

    def get_key_value_list(self,content):
        valuelist = list()
        for key, value in sorted(dict.items(self.remove_parsing_failstring(content))):
                valuelist.append(value)
        return valuelist


    def get_config_from_file(self,filename,keyname):
        configlist = list()
        filepath =os.path.join(os.getcwd(), filename)
        json_data = open(filepath).read()
        d = json.loads(json_data)
        for key, value in dict.items(d):
            if key ==  keyname:
                configlist = value.split("\n")
        return configlist






import smtplib
from fluentmail import FluentMail,TLS
import base64

class sqa_mail:
    def __init__(self):
        self.mail_host = "smtp.office365.com"
        self.mail_user ="sqa.testrail@lileesystems.com"
        self.mail_pass = "5tgb^YHN"
        self.sender = "sqa.testrail@lileesystems.com"

    def send_mail(self,receivers,mail_subject,mail_body):
        try:
            mail = FluentMail(self.mail_host, 587, TLS)
            mail.credentials(self.mail_user,  self.mail_pass)\
                .from_address(self.sender)\
                .to(receivers)\
                .subject(mail_subject)\
                .body(mail_body)\
                .send()
            print 'send mail success'
        except smtplib.SMTPException ,ex:
            print "send mail error:"+str(ex)

'''
mutlip thread for ssh connect
'''

from Queue import Queue
from threading import Thread
from SSHConsole import SSHConnect

class multip_ssh_worker(Thread):
    def __init__(self,queue):
        Thread.__init__(self)
        self.queue =queue
        self.loggname ="worker"
        self.logger = logging.getLogger('%s.multip_ssh_worker'%(self.loggname))


    def run(self):
        while True:
            try:
                Server_ip,Server_port,command,timeout,mode  = self.queue.get()
                sshconnect = SSHConnect(Server_ip,Server_port,logname = self.loggname)
                sshconnect.connect()
                sshconnect.write_command(command,timeout,mode)
                self.queue.task_done()
            except Exception, e:
              message = "Exception : "+ str(e)
              logging.debug(message)
              self.queue.task_done()

logger = Log("worker","worker")

if __name__ == '__main__':

    '''
    apiclient = APIClient('http://10.2.8.133:8000/api/')
    data ={"device_name":'R5-LMC',"profile_name":'basic_config'}
    result = apiclient.send_get("ProfileByName",data)
    content = result[0]["content"]
    result =  json.loads(content.replace('"','\\"').replace("u'","'").replace("'","\""))
    print result["eth3_ip"]
    #for item in datalist:
    #    print item
    '''
    server_ip = "192.168.10.1"
    server_port =22
    command = "ping 8.8.8.8"
    timeout = 10
    mode ="shell"
    queue = Queue()
    for x in range(6):
        worker = multip_ssh_worker(queue)
        worker.daemon =True
        worker.start()

    for x in range(6):
        queue.put((server_ip,server_port,command,timeout,mode))
    queue.join()
    # Mail testing
    #sqamail = sqa_mail()
    #sqamail.send_mail("ricky.wang@lileesystems.com","sqa mail testing",u"test 123 go")


