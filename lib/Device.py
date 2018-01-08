import logging
import os
from Image import  *
from TelnetConsole import *
from SSHConsole import *
from Tool import *

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
        self.branch_version=""
        self.testrail_build_version = ""
        self.device_product_name ="LMC-5500-1E8R1H05"
        self.device_set_lilee_mode =False
        self.device_type = 'lmc'
        self.device_hostname =''
        self.device_register_MAC=''
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
            bashcommandlist = ["ifconfig","ping","ip route"] #Add "ip" for ip table modifying
            filter_result =  list(lileecommand for lileecommand in bashcommandlist if lileecommand in command)
            if len(filter_result) >0:
                command_mode = "shell"
            else:
                lileecommandlist = ["config","debug","update","show","diag","create","yes","no","\x03","\n"]
                filter_result =  list(lileecommand for lileecommand in lileecommandlist if lileecommand in command)
                if len(filter_result) >0:
                    command_mode ='lilee'
        else:
            self.device_set_lilee_mode = False
            return 'lilee'
        #print ("command mode is %s" % command_mode)
        return command_mode

    def _escape_ansi(self,line):
        ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
        return ansi_escape.sub('', line).replace("\r","")

    def device_send_command(self,command,timeout =5):
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
        if commandresult == False: print self.target_response
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
        if(self.device_send_command("show running-configuration",10)):
            return self.target_response
        else :
            return ""

    def device_get_running_config_list(self):
        no_config_list = {'localdomain','>'}
        configlist =list()
        for config in list(self.device_get_running_config().split("\n")):
            match = [s for s in no_config_list if s in config]
            if len(match) == 0:
                configlist.append(config)
        return configlist

    def device_set_configs(self,configlist):
        timeout = 15
        runningconfig = self.device_get_running_config()
        for config in configlist:
            if config not in runningconfig:
                if 'enable' in config or 'disable' in config or 'controller' in config or '-ghz' in config or 'ac-mode' in config: #config interface wlan
                    timeout = 120
                sendresult = self.device_send_command(config,timeout)
                if sendresult == False:
                    print 'set fail:'+ self.target_response
                    print 'set again:'+config
                    self.device_send_command("\x03",timeout)
                    self.device_send_command(config,timeout)


    def device_set_no_config(self,configlist):
        runningconfig = self.device_get_running_config()
        for config in configlist:
            if config in runningconfig:
                if 'enable' in config or 'disable' in config:
                    timeout = 30
                noconfig = "no %s"%(config)
                self.device_send_command(noconfig)

    def device_no_config(self):
        self.device_send_command("update terminal paging disable")
        no_set_list = {'host name','iccid','terminal','config app-engine 0 disable','config interface maintenance 0'}
        runningconfig = self.device_get_running_config_list()
        for config in reversed(runningconfig):
            match = [s for s in no_set_list if s in config]
            if len(match) == 0:
                timeout = 3
                if "enable"  in config or 'disable' in config or 'controller' in config:
                    timeout = 30
                noconfig = "no %s"%(config)
                sendresult =  self.device_send_command(noconfig,timeout)
                if sendresult == False:
                    print 'set fail:'+ self.target_response
                    print 'set again:'+config
                    self.device_send_command("\x03",timeout)
                    self.device_send_command(noconfig,timeout)

    def device_reboot(self):
        if self.device_send_command("reboot"):
            time.sleep(60)
            self.target = self.device_connect()
            timer_item = 0
            while self.target is None and timer_item<30:
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
                self.bios_version = sub_match[0].strip()

        versionmatchresult = self.device_send_command_match("show version",5,"Version")
        if versionmatchresult:
            sub_match = re.findall(r'LileeOS Version (.*)\n',self.target_response)
            if sub_match:
                self.build_image = sub_match[0].strip()
                if self.build_image!="":
                    self.testrail_build_version = self.build_image.replace("LileeOS_","")
                    self.branch_version= self.build_image.split("_")[1]
            sub_match = re.findall(r'Recovery Mode Image Version (.*)\n', self.target_response)
            if sub_match:
                self.boot_image=  sub_match[0].strip()
            sub_match = re.findall(r'Product Name: (.*)\n', self.target_response)
            if sub_match:
                self.device_product_name=  sub_match[0].strip()
                if self.device_product_name!="":
                    self.device_type = self.device_product_name.split("-")[0].lower().strip()

    def device_get_register_MAC(self,interface):
        command = "show interface %s detail"%(interface)
        matchstring = "Interface : %s"%(interface)
        matchresult = self.device_send_command_match(command,10,matchstring)
        if matchresult:
            sub_match = re.findall('HW address : (.*) MTU', self.target_response)
            if sub_match:
                self.device_register_MAC= sub_match[0].strip()

    def device_get_hostname(self):
        matchresult = self.device_send_command_match("show host name",5,"Host Name :")
        if matchresult:
            sub_match = re.findall('Host Name : (.*)\n', self.target_response)
            if sub_match:
                self.device_hostname = sub_match[0].strip()

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

class Device_Profile():
        def __init__(self,hostname,branch_version,maintenanceip,maintenanceMAC):
            self.hostname = hostname
            self.branch_version = branch_version
            self.maintenanceip = maintenanceip
            self.maintenanceMAC =maintenanceMAC
            self.apiclient =APIClient('http://10.2.8.133:8000/api/')
            self.device_profile = self.get_device_profile("basic_config")


        #### Get api response data
        def __get_profile_content(self,profile_name):
            data ={"device_name":self.hostname,"profile_name":profile_name}
            return self.apiclient.send_get("ProfileByName",data)

        def __get_config_content(self,config_name):
            data ={"version":self.branch_version,"configname":config_name}
            return self.apiclient.send_get("ConfigByName",data)

        def __get_check_content(self,check_name):
            data ={"version":self.branch_version,"checkname":check_name}
            return self.apiclient.send_get("CheckCommandByName",data)


        ### Get Device info data
        def get_device_info(self):
            if self.maintenanceMAC =='' or   self.maintenanceip =='':
                data ={"hostname": self.hostname}
                result =self.apiclient.send_get("DeviceInfoByName",data)
            else:
                data ={"mac":self.maintenanceMAC,"ipaddress":self.maintenanceip}
                result = self.apiclient.send_get("DeviceInfoByMac",data)
            return result

        ### Get Device profile
        def get_device_profile(self,profile_name):
            parsingdata =PassProfileJson()
            result = self.__get_profile_content(profile_name)
            content = result[0]["content"]
            return parsingdata.remove_parsing_failstring(content)

        def get_device_all_profile(self):
            profilelist = list()
            contentlist = self.__get_profile_content("All")
            for item in contentlist:
                profilelist.append(item["content"])
            return profilelist

        def get_device_profile_list(self,profile_name,key_name):
            configlist =list()
            result = self.__get_profile_content(profile_name)
            if result:
                content = result[0]["content"]
                if '{' in content and '}' in content:
                    parsingdata =PassProfileJson()
                    configlist = parsingdata.get_configlist_by_key(content,key_name)

                else:
                    configlist = content.split("\n")
            return configlist

        def get_device_profile_value(self,profile_name,key_name):
            key_value =''
            result = self.__get_profile_content(profile_name)
            if result:
                content = result[0]["content"]
                if '{' in content and '}' in content:
                    parsingdata =PassProfileJson()
                    key_value = parsingdata.get_value_by_key(content,key_name)
            return key_value

        # Get Configuration Profile for test case
        def get_config_profile_list(self,config_name,key_name ='All'):
            configlist =list()
            checkconfiglist = list()
            result = self.__get_config_content(config_name)
            if result:
                profile = result["profile"]
                if '{' in profile and '}' in profile:
                    parsingdata =PassProfileJson()
                    configlist = parsingdata.get_configlist_by_key(profile,key_name)
                else:
                    configlist = profile.split("\n")

            pat = r'(?<=\[).+?(?=\])'
            for config in configlist:
                replaceconfig =self.check_device_value(config)
                checkconfiglist.append(replaceconfig)
            return checkconfiglist



        def get_config_profile_value(self,profile_name,key_name):
            key_value =''
            result = self.__get_profile_content(profile_name)
            if result:
                profile = result["profile"]
                if '{' in profile and '}' in profile:
                    parsingdata =PassProfileJson()
                    key_value = parsingdata.get_value_by_key(profile,key_name)
            return key_value

        def get_check_values(self,check_name):
            checklist =list()
            result = self.__get_check_content(check_name)
            if result:
                checkinfo = result["checkinfo"]
                if '{' in checkinfo and '}' in checkinfo:
                    parsingdata =PassProfileJson()
                    checklist = parsingdata.get_key_value_list(checkinfo)

            return checklist

        def get_check_value_bykey(self,check_name,key_name):
            key_value =''
            result = self.__get_check_content(check_name)
            if result:
                content = result["content"]
                if '{' in content and '}' in content:
                    parsingdata =PassProfileJson()
                    key_value = parsingdata.get_value_by_key(content,key_name)
            return key_value

        def check_device_value(self, checktext):
            pat = r'(?<=\[).+?(?=\])'
            matchlist = re.findall(pat, checktext)
            if matchlist:
                 for match in matchlist:
                    originvalue ="["+match+"]"
                    value = str(self.device_profile[match])
                    checktext = checktext.replace(originvalue,value)
            return checktext


if __name__ == '__main__':

    mainlogger = Log("Device","device_test")

    device_profile = Device_Profile("R5-LMC","3.3","10.2.11.51","00:18:7d:20:4e:d4")


    configlist = device_profile.get_config_profile_list("Tunnel_Interface_Pretesting_Server_Config")

    for config in configlist:
        print config



    #telnet_device =Device_Tool("10.2.11.58",2041,"telnet","admin","admin","device_test")

    #result = telnet_device.device_reboot()

    #logger.info("result :%s, response: %s"%(result,telnet_device.target_response))

    #print telnet_device.device_send_command_match("show interface all",5,"maintenance 0(.*) up")

    #print telnet_device.device_send_command_match("cat /proc/partitions",5,"sda")

    #device =Device_Tool("10.2.52.51",0,"ssh","admin","admin","device_test")

    #device =Device_Tool("10.2.52.53",22,"ssh","admin","admin","device_test")

    #if device:
    #    device.device_get_hostname()
    #    device.device_get_register_MAC("maintenance 0")


    #    print device.device_hostname
    #    print device.device_register_MAC
        #command ="update boot system-image http://10.2.10.17/weekly/v3.3/sts1000_u_3.3_build46.img"
        #result =  device.device_send_command_match("ping -c5 10.2.10.17",2,"64 bytes from 10.2.10.17: icmp_seq=5")

        #print result
        #print device.target_response
        #if result:
            #result = device.device_send_command(("yes"))
            #print result
            #print device.target_response












