__author__ = 'ricky.wang'
import telnetlib
import time
import re
import httplib2
import logging
import paramiko

class SSHConnect(object):

    def __init__(self,ipaddress,port=22,username="admin",password="admin",logname="SSHConnect",timeout=10):
        self.ipaddress = ipaddress
        self.port =port
        self.username = username
        self.password=password
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sshresult = ""
        self.IsConnect =False
        self.remote_conn = None
        self.logger = logging.getLogger('%s.ssh'%(logname))
        self.logger.info('creating the sub log for SSHConnect')

    def connect(self):
        try:
            self.ssh.connect(self.ipaddress, port=self.port, username=self.username, password= self.password, timeout=int(10))
            self.sshresult = ""
            time.sleep(1)
            if(self.ssh):
                self.IsConnect= True
                self.remote_conn = self.ssh.invoke_shell()
                time.sleep(2)
                self.sshresult =  self.remote_conn.recv(5000)
            else:
                self.IsConnect =False
            self.logger.info("connect status :%s"%(self.IsConnect))

        except Exception,ex:
            self.logger.error("[connect]ssh login fail:%s "%(str(ex)))
            self.IsConnect =False

    def disconnect(self):
        try:
            self.ssh.close()
            time.sleep(1)
            self.IsConnect =False
            self.logger.info("connect status :%s"%(self.IsConnect))
        except Exception,ex:
            self.logger.error("[disconnect]ssh disconnect fail:%s "%(str(ex)))
            self.IsConnect =False

    def __set_command_mode(self,mode):
        mode_result = False
        self.remote_conn.send("\n")
        time.sleep(2)
        response_result =  self.remote_conn.recv(5000)
        if mode == "shell":
            if "bash" in response_result:
                mode_result = True
            elif "localdomain" in response_result:
                self.remote_conn.send("%s\n"%("diag shell"))
                time.sleep(2)
                response_result = self.remote_conn.recv(5000)
                if "Password" in response_result:
                    self.remote_conn.send("%s\n"%("Unsupported!"))
                    time.sleep(2)
                    response_result =  self.remote_conn.recv(5000)
                    if "bash" in response_result:
                        mode_result =True

        elif mode == "lilee":
            if "localdomain" in response_result:
                mode_result = True

            elif "bash" in response_result:
                self.remote_conn.send("%s\n"%("exit"))
                time.sleep(2)
                response_result = self.remote_conn.recv(5000)
                if "localdomain" in response_result:
                    mode_result =True
        else:
            mode_result=True
        return mode_result

    def write_command(self, command,timeout,mode,logflag =True):
        try:
            mode_result = True
            if(self.ssh):
                #add for nat testing
                if self.__set_command_mode(mode):
                    self.remote_conn.send("%s\n"%(command))
                    time.sleep(timeout)
                    self.sshresult = self.remote_conn.recv(5000)
                    if logflag == True:
                        self.logger.info(self.sshresult)
                    return True

            else:
                self.logger.info("Connection not opened.")
        except Exception,ex:
            self.logger.error("[write_command]write command fail:%s "%(str(ex)))
            self.IsConnect =False
            self.ssh.close()

    def write_command_match(self,command,timeout,mode,result):
         try:
            if(self.ssh):
                if self.__set_command_mode(mode):
                    self.remote_conn.send((command + "\n").encode('ascii'))
                    time.sleep(timeout)
                    self.sshresult = self.remote_conn.recv(5000)
                    match_result =self.__Patern_Match(result, self.sshresult)
                    return match_result
         except Exception,ex:
             self.logger.error("[write_multip_command_match]write command fail:%s "%(str(ex)))
             return False

    def write_multip_command_match(self,commandlist,timeout,mode,resultlist):
         try:
             if(self.ssh):
                if self.__set_command_mode(mode):
                    for index,command in enumerate(commandlist):
                        result = resultlist[index]
                        self.remote_conn.send((command + "\n").encode('ascii'))
                        time.sleep(timeout)
                        self.sshresult = self.remote_conn.recv(5000)
                        match_result =self.__Patern_Match(result, self.sshresult)
                        if (match_result == False):
                            self.logger.error("[write_multip_command_match]command(%s):%s "%(command,match_result))
                            return False
                    return True
         except Exception,ex:
            self.logger.error("[write_multip_command_match]write command fail:%s "%(str(ex)))
            return False

    def shell_message(self):
        message =""
        if(self.ssh):
            message =  self.remote_conn.recv(5000)
        return message

    def __Patern_Match(self,pattern,text):
        if '&&' in pattern:
            patterns = pattern.split("&&")
            for pat in patterns:
                p = re.compile(pat)
                match = p.search(text)
                if (match == None):
                    return False
            return True
        else:
           p = re.compile(pattern)
           match = p.search(text)
           if (match == None):
               print "pattern : %s , text: %s"%(pattern,text)
               return False
           else:
               return True


def set_log(filename,loggername):
    logger = logging.getLogger(loggername)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh = logging.FileHandler(filename)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger


if __name__ == '__main__':


    logger = set_log("sshconsole.log","SSHConnect")

    logger.info("SSH")


    sshconnect = SSHConnect("10.2.52.53")
    sshconnect.connect()
    if(sshconnect.IsConnect):
        #sshconnect.write_command("reboot",2)
        #time.sleep(120)
        #sshconnect.connect()
        #sshconnect.write_command("show version",2,"lilee")
        result = sshconnect.write_command_match("cat /dev/ttyUSB1",10,"shell","GSV&&GPGSA&&RMC")
        print result
        print sshconnect.sshresult





