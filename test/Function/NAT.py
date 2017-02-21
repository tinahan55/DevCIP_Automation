__author__ = 'mandy.wu'
from lib.Device import *
from lib.Configuration import *
import os
from time import gmtime, strftime
from lib.SSHConsole import *



#def NAT_port_setup(include port and app-engine)
#def dhcp_setup
#dnat


def device_check_info(logger, device, checkitem, checkcommand, checkmatch):
    title = "[%s][%s]"%(checkitem, checkcommand)
    logger.info("%s starting"%(title))
    checkresult = device.device_send_command_match(checkcommand, 5, checkmatch)
    logger.info("%s check %s result : %s"%(title, checkmatch, checkresult))
    if checkresult == False:
        logger.info("%s check %s error : %s"%(title, checkmatch, device.target_response))


def NAT_port_setup(device):
    configlist = list()
    # port
    port_type = "port"
    vlan_index = 100
    port_index = 1
    vlan_tagged = "untagged"
    port_tagged = "untagged"

    #vlan
    ip_mode = "static"
    ipaddress = "10.1.4.254"
    netmask = "255.255.255.0"
    vlan_description = "NAT-test"

    interface = Interface("Port")
    configlist.extend(interface.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))

    function = Function("vlan")
    configlist.extend(function.get_vlan(vlan_index, vlan_description, ip_mode, ipaddress, netmask))

    device.device_set_configs(configlist)

    #verify command
    checkitem = "NAT_port_setup"
    checkcommandlist = ["show interface all", "show interface vlan %s detail"%(vlan_index)]

    checkitemlist = ["vlan %s"%(vlan_index), "Operational : up | MTU : 1500"]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def NAT_app_engine_setup(device):
    configlist = list()
    # app-engine
    port_type = "app-engine"
    vlan_index = 100
    vlan_tagged = "untagged"

    port_index = 1
    port_tagged = "untagged"

    interface = Interface("app-engine")
    configlist.extend(interface.get_port_interface(port_index,port_type,vlan_index,vlan_tagged,port_tagged))

    device.device_set_configs(configlist)

    #verfiy command
    checkitem = "NAT_app_engine_setup"
    checkcommandlist = ["show app-engine 0 info"]

    checkitemlist = ["Operational : Running"]

    logger.info("[%s]Starting"%(checkitem))
    for index,value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger,device,checkitem,value,checkmatch)

def NAT_dhcp(device):
    configlist = list()
    pool_name = "test-dhcp"
    pool_start_ip = "10.1.4.153"
    pool_end_ip = "10.1.4.153"
    netmask = "255.255.255.0"
    default_gateway = "10.1.4.254"
    dns_server_list = ["168.95.1.1"]
    dns_priority_list =[1]
    dhcp_interface = "vlan 100"

    function = Function("dhcp")
    configlist.extend(function.get_dhcp_pool(pool_name, pool_start_ip, pool_end_ip, netmask, default_gateway))
    configlist.extend(function.set_dhcp_pool_dns(pool_name, dns_server_list, dns_priority_list))
    configlist.extend(function.set_dhcp_pool_interface(pool_name,dhcp_interface))
    configlist.extend(function.get_service("dhcp-server"))


    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT_dhcp"
    checkcommandlist = ["show dhcp-server lease"]

    checkitemlist = ["%s"%(pool_start_ip)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger, device, checkitem, value, checkmatch)


def NAT_classifier(device):
    configlist = list()
    index = 100
    description = "automatically added for port forwarding"
    ip_type = "protocol"
    protocol_type = "tcp"
    port_mode = "dport"
    port_no = 2222
    ip_address = "10.1.4.226"

    function = Function("classifier")
    configlist.extend(function.get_classifier(index,description,ip_type, protocol_type, port_mode, port_no,ip_address))

    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT_classifier"
    checkcommandlist = ["show classifier %s"%(index)]

    checkitemlist = ["Classifier ID : %s"%(index), "Protocol : %s"%(protocol_type)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger, device, checkitem, value, checkmatch)


def NAT(device):
    configlist = list()
    nat_type = "dnat"
    port = 22
    interface = "maintenance"
    interface_index = 0
    classifier_index = 100
    ip = "10.1.4.153"
    priority = 1

    function = Function("NAT")
    configlist.extend(function.get_nat(nat_type, port, interface, interface_index, classifier_index, ip, priority))

    device.device_set_configs(configlist)

    #add verify command
    checkitem = "NAT"
    checkcommandlist = ["show %s"%(nat_type)]

    checkitemlist = ["%s"%(ip)]

    logger.info("[%s]Starting"%(checkitem))
    for index, value in enumerate(checkcommandlist):
        checkmatch = checkitemlist[index]
        device_check_info(logger, device, checkitem, value, checkmatch)

def service_enable(device):
    configlist = list()
    service_name = "http"
    function = Function("service_enable")
    configlist.extend(function.get_service(service_name))
    device.device_set_configs(configlist)

    checkitem = "service_enable"
    logger.info("[%s]Starting"%(checkitem))

'''
class SSHConnect_test(object):

    def __init__(self, ipaddress, port, username="root", password="admin", logname="SSHConnect_test"):
        self.ipaddress = ipaddress
        self.port = port
        self.username = username
        self.password=password
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.sshresult = ""
        self.IsConnect = False
        #self.IsLogin = False
        #self.logger = logging.getLogger('%s.ssh'%(logname))
        #self.logger.info('creating the sub log for SSHConnect')


    def connect(self):
        try:
            self.ssh.connect(self.ipaddress, port=2222, username=self.username, password=self.password, timeout=int(10))
            if (self.ssh):
                self.IsConnect = True
                print "IsConnect = True"
            else:
                self.IsConnect = False
                print "IsConnect = False"

        except Exception, ex:
            print "[connect]ssh connect fail:%s" % (str(ex))
            self.IsConnect = False
            self.ssh.close()


    def __ssh_login(self, remote_conn):
        #login_result = False
        response_result = remote_conn.recv(5000)
        print "ssh status show now: %s" % (response_result)
        time.sleep(3)
        if "localhost" in response_result:
            print "[dnat success] You already login successfully."
            login_result = True
        else:
            if "login" in response_result:
                remote_conn.send("%s\n" % (self.username))
                time.sleep(30)
                response_result = remote_conn.recv(5000)
                if "password" in response_result:
                    remote_conn.send("%s\n" % (self.password))
                    time.sleep(5)
                    response_result = remote_conn.recv(5000)
                    if "localhost" in response_result:
                        print "login success"
                        #login_result = True
                    else:
                        print "password fail"
                else:
                    print "username fail"
            else:
                print "login fail"
        #return login_result



    def ssh_write_command(self, command, timeout, dnat_ip):
        try:
            if (self.ssh):
                remote_conn = self.ssh.invoke_shell()
                if self.__ssh_login(remote_conn):
                    time.sleep(timeout)
                    response_result = remote_conn.recv(5000)
                    print response_result

                                        if dnat_ip in response_result:
                                            print "ip correct and dnat success"
                                        else:
                                            print "ip wrong and dnat fail"

            else:
                logger.info("ssh connection not opened")
        except Exception, ex:
            logger.info("[ssh_write_command]write command fail:%s " % (str(ex)))
            self.IsConnect = False
            self.ssh.close()
'''



def set_log(filename, loggername):
    logpath = os.path.join(os.getcwd(), 'log')
    if not os.path.exists(logpath):
        os.makedirs(logpath)
    filepath = os.path.join(logpath, filename)
    logger = logging.getLogger(loggername)
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



#main( connect -> initial setup -> catch config -> compare -> append config -> show and verify)
if __name__ == '__main__':

    logfilename = "NAT%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename, "NAT_testing")
    ip = "10.2.59.160"
    port = 22
    mode = "ssh"
    username = "admin"
    password = "admin"
    device = Device_Tool(ip, port, mode, username, password, "NAT")

    dport = 2222
    connecttype = "ssh"
    dnat_username = "root"

    if device:
        device.device_get_version()
        logger.info("Device Bios Version: %s"%(device.bios_version))
        logger.info("Lilee OS Version (build image): %s"%(device.build_image))
        logger.info("Recovery Image Version: %s"%(device.boot_image))

        NAT_port_setup(device)
        NAT_app_engine_setup(device)
        NAT_dhcp(device)
        NAT_classifier(device)
        NAT(device)
        service_enable(device)


    #sshconnect = SSHConnect_test("10.2.59.160", 2222)
    #sshconnect.connect()
    #if (sshconnect.IsConnect):
            #sshconnect.ssh_write_command("ifconfig", 5, "10.1.4.153")

    logger.info("ssh test starting")

    sshconnect = SSHConnect(ip, dport, dnat_username, password, "NAT")
    sshconnect.connect()
    if (sshconnect.IsConnect):
        sshconnect.write_command("ifconfig", 5, mode)
        print sshconnect.sshresult


