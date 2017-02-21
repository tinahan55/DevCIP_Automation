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




