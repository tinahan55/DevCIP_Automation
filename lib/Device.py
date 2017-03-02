import logging
import os
from Image import  *
from TelnetConsole import *
from SSHConsole import *
from Tool import Log

class Device_Tool(object):

    def __init__(self,ipaddress,port,connecttype,username = "admin",password ="admin",logname=""):
        self.ipaddress = ipaddress
        self.port = port
        self.username = username
        self.password=password
        self.connecttype = connecttype
        self.logname = logname
        self.logger = logging.getLogger('%s.Device_Tool'%(self.logname))
        self.logger.info('creating the sub log for Device_Tool')
        self.target_response = ""
        self.bios_version = ""
        self.boot_image = ""
        self.build_image =""
        self.testrail_build_version = ""
        self.device_product_name ="LMC-5500-1E8R1H05"
        self.device_set_lilee_mode =False
        self.device_type = 'lmc'
        self.target = self.device_connect()


    def device_connect(self):
        self.target_response =""
        if self.connecttype == "telnet":
            telnet_console =Telnet_Console(self.ipaddress,self.port,self.username,self.password,self.logname)
            result = telnet_console.login()
            if result ==True:
                self.target_response = self._escape_ansi(telnet_console.telnetresult)
                return telnet_console
            else:
                return None

        elif self.connecttype == "ssh":
            try:
                ssh_console = SSHConnect(self.ipaddress,self.port,self.username,self.password,self.logname)
                ssh_console.connect()
                if ssh_console.IsConnect:
                    self.target_response = self._escape_ansi(ssh_console.sshresult)
                    return ssh_console
                else:
                    return None
            except Exception ,e:
                    return None


    def __device_check_mode(self,command):
        if self.device_set_lilee_mode == False:
            command_mode = 'shell'
            bashcommandlist = ["ifconfig","ping"]
            filter_result =  list(lileecommand for lileecommand in bashcommandlist if lileecommand in command)
            if len(filter_result) >0:
                command_mode = "shell"
            else:
                lileecommandlist = ["config","update","show","diag","create","yes","no","\x03","\n"]
                filter_result =  list(lileecommand for lileecommand in lileecommandlist if lileecommand in command)
                if len(filter_result) >0:
                    command_mode ='lilee'
        else:
            self.device_set_lilee_mode = False
            return 'lilee'
        return command_mode

    def _escape_ansi(self,line):
        ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
        return ansi_escape.sub('', line).replace("\r","")

    def device_send_command(self,command):
        timeout = 5
        commandresult = False
        commandresponse = ""
        command_mode =self.__device_check_mode(command)
        if self.connecttype == "telnet":
            if self.target!=None:
                commandresult = self.target.send_command(command,timeout,command_mode)
                self.target_response = self._escape_ansi(self.target.telnetresult)

        elif self.connecttype =="ssh":
            if self.target!=None:
                commandresult = self.target.write_command(command,timeout,command_mode)
                self.target_response = self._escape_ansi(self.target.sshresult)
        return commandresult

    def device_send_command_match(self,command,timeout,matchresult):
        commandresult = False
        command_mode =self.__device_check_mode(command)
        if self.connecttype == "telnet":
            if self.target!=None:
                commandresult = self.target.send_command_match(command,timeout,command_mode,matchresult)
                self.target_response = self._escape_ansi(self.target.telnetresult)

        elif self.connecttype =="ssh":
            if self.target!=None:
                commandresult = self.target.write_command_match(command,timeout,command_mode,matchresult)
                self.target_response = self._escape_ansi(self.target.sshresult)

        return commandresult

    def device_send_multip_command_match(self,commandlist,timeout,matchresultlist):
        timeout = 10
        commandresult = False
        command_mode ="lilee"
        if self.connecttype == "telnet":
            if self.target!=None:
                commandresult = self.target.send_multip_command_match(commandlist,timeout,command_mode,matchresultlist)
                self.target_response = self._escape_ansi(self.target.telnetresult)
                print self.target_response

        elif self.connecttype =="ssh":
            if self.target!=None:
                commandresult = self.target.write_multip_command_match(commandlist,timeout,command_mode,matchresultlist)
                self.target_response = self._escape_ansi(self.target.sshresult)

        return commandresult

    def get_device_message(self):

        timeout = 10
        commandresult = False
        command_mode ="lilee"
        if self.connecttype == "telnet":
            if self.target!=None:
                return self.target.console_message()
        elif self.connecttype =="ssh":
            if self.target!=None:
                return self.target.shell_message()


    def device_get_running_config(self):
        if(self.device_send_command("show running-configuration")):
            return self.target_response
        else :
            return ""

    def device_get_running_config_list(self):
        config = self.device_get_running_config()
        return list(runningconfig for runningconfig in config.split("\n") if '>' not in runningconfig)

    def device_set_configs(self,configlist):
        runningconfig = self.device_get_running_config()
        for config in configlist:
            if config not in runningconfig:
                self.device_send_command(config)

    def device_set_no_config(self,configlist):
        runningconfig = self.device_get_running_config()
        for config in configlist:
            if config in runningconfig:
                noconfig = "no %s"%(config)
                self.device_send_command(noconfig)

    def device_reboot(self):
        if self.device_send_command("reboot"):
            time.sleep(60)
            self.target = self.device_connect()
            timer_item = 0
            while self.target is None and timer_item<20:
                time.sleep(10)
                timer_item+=1
                self.target = self.device_connect()

            if self.target is not None:
                return True
            else:
                return False

    def device_get_version(self):
        biosmatchresult = self.device_send_command_match("dmidecode -t 0",5,"BIOS Information")
        if biosmatchresult:
            sub_match = re.findall('Version: (.*)\n', self.target_response)
            if sub_match:
                self.bios_version = sub_match[0]

        versionmatchresult = self.device_send_command_match("show version",5,"Version")
        if versionmatchresult:
            sub_match = re.findall(r'LileeOS Version (.*)\n',self.target_response)
            if sub_match:
                self.build_image = sub_match[0]
                if self.build_image!="":
                    self.testrail_build_version = self.build_image.replace("LileeOS_","")
            sub_match = re.findall(r'Recovery Mode Image Version (.*)\n', self.target_response)
            if sub_match:
                self.boot_image=  sub_match[0]
            sub_match = re.findall(r'Product Name: (.*)\n', self.target_response)
            if sub_match:
                self.device_product_name=  sub_match[0]
                if self.device_product_name!="":
                    self.device_type = self.device_product_name.split("-")[0].lower()

    def device_get_response(self, command):
        timeout = 5
        commandresult = False
        command_mode = self.__device_check_mode(command)
        if self.connecttype == "telnet":
            if self.target != None:
                commandresult = self.target.send_command(command, timeout, command_mode)
                self.target_response = self._escape_ansi(self.target.telnetresult)
                return self.target_response
        elif self.connecttype == "ssh":
            if self.target != None:
                commandresult = self.target.write_command(command, timeout, command_mode)
                self.target_response = self._escape_ansi(self.target.sshresult)
                return self.target_response
        #return commandresult



if __name__ == '__main__':

    mainlogger = Log("Device","device_test")

    #telnet_device =Device_Tool("10.2.11.58",2041,"telnet","admin","admin","device_test")

    #result = telnet_device.device_reboot()

    #logger.info("result :%s, response: %s"%(result,telnet_device.target_response))

    #print telnet_device.device_send_command_match("show interface all",5,"maintenance 0(.*) up")

    #print telnet_device.device_send_command_match("cat /proc/partitions",5,"sda")

    #device =Device_Tool("10.2.52.51",0,"ssh","admin","admin","device_test")

    device =Device_Tool("10.2.11.58",2041,"telnet","admin","admin","device_test")

    if device:
        print device.device_reboot()

        #command ="update boot system-image http://10.2.10.17/weekly/v3.3/sts1000_u_3.3_build46.img"
        #result =  device.device_send_command_match("ping -c5 10.2.10.17",2,"64 bytes from 10.2.10.17: icmp_seq=5")

        #print result
        #print device.target_response
        #if result:
            #result = device.device_send_command(("yes"))
            #print result
            #print device.target_response












