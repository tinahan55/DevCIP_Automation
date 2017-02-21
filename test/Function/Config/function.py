from lib.Configuration import *

class dhcppool(object):
    def __init__(self,pool_name,pool_start_ip,pool_end_ip,netmask,default_gatway):
        self.pool_name = pool_name
        self.pool_start_ip =pool_start_ip
        self.pool_end_ip = pool_end_ip
        self.netmask = netmask
        self.default_gateway =default_gatway
        self.dns_server_list = list()
        self.dns_priority_list = list()
        self.interface = None
        self.configlist = list()
        self.function = Function("dhcppool")
        self.__set_pool()

    def __set_pool(self):
        self.configlist.extend(self.function.get_dhcp_pool(self.pool_name, self.pool_start_ip, self.pool_end_ip, self.netmask, self.default_gateway))

    def get_pool_dns(self,dns_server_list,dns_priority_list):
        self.configlist.extend(self.function.set_dhcp_pool_dns(self.pool_name, dns_server_list , dns_priority_list))

    def get_pool_to_interface(self,inteface):
        self.configlist.extend(self.function.set_dhcp_pool_interface(self.pool_name,inteface))

class classifier(object):
    def __init__(self,index):
        self.index = index
        self.description = ""
        self.ip_type=""

        self.protocol_type = ""
        self.port_mode=""
        self.ipaddress =""
        self.ip_type=""
        self.port_no=""
        self.configlist = list()

    def __get_classifier(self):
        function = Function("classifier")
        self.configlist.extend(function.get_classifier(self.index,self.description,
                                                            self.ip_type, self.protocol_type, self.port_mode, self.port_no, self.ipaddress))

    def __set_initial(self):
        self.ip_type = "protocol"
        self.port_mode=""
        self.ipaddress =""
        self.ip_type=""
        self.port_no=""


    def get_protocol_classifier(self,ipaddress,protocol_type,port_mode,port_no):
        self.__set_initial()
        self.ip_type = "protocol"
        self.protocol_type = protocol_type
        self.port_mode =port_mode
        self.port_no=port_no
        self.ipaddress = ipaddress
        self.__get_classifier()


    # for source and destination ip
    def get_ip_classifier(self,ipaddress):
        self.__set_initial()
        self.ip_type ="ip"
        self.ip_type=ipaddress
        self.__get_classifier()

class vlan(object):
    def __init__(self,vlan_index,vlan_description,ip_mode,ip_address,ip_netmask):
        self.vlan_index = vlan_index
        self.vlan_description = vlan_description
        self.ip_mode = ip_mode
        self.ip_address = ip_address
        self.ip_netmask = ip_netmask
        self.configlist = list()
        self.__set_vlan()

    def __set_vlan(self):
        function = Function("vlan")
        self.configlist.extend(function.get_vlan(self.vlan_index ,self.vlan_description, self.ip_mode,  self.ip_address,self.ip_netmask))

    def get_port_vlan(self,port_index,port_tagged,vlan_tagged):
        port_type = "port"
        interface = Interface("Port")
        self.configlist.extend(interface.get_port_interface(port_index,port_type,self.vlan_index,vlan_tagged,port_tagged))

    def get_appengine_vlan(self,port_tagged,vlan_tagged):
        port_type = "app-engine"
        port_index = 1
        interface = Interface("app-engine")
        self.configlist.extend(interface.get_port_interface(port_index,port_type,self.vlan_index,vlan_tagged,port_tagged))

    def get_dhcppool_vlan(self,pool_name,pool_start_ip,pool_end_ip,netmask,default_gatway,dns_server_list,dns_priority_list):
        dhcp_interface =  "vlan %s"%(self.vlan_index)
        vlanpool = dhcppool(pool_name,pool_start_ip,pool_end_ip,netmask,default_gatway)
        #dns option list
        if len(dns_server_list)>0:
            vlanpool.get_pool_dns(dns_server_list,dns_priority_list)

        vlanpool.get_pool_to_interface(dhcp_interface)
        self.configlist.extend(vlanpool.configlist)

class nat(object):
    def __init__(self):
        self.nat_type = ""
        self.port = ""
        self.ip =""
        self.classifier_index = ""
        self.priority = 0
        self.interface =""
        self.configlist = list()

    def __set_initial(self):
        self.nat_type = ""
        self.port = ""
        self.ip =""
        self.interface =""
        self.classifier_index = 0
        self.priority = 0

    def __get_nat(self):
        function = Function("NAT")
        self.configlist.extend(function.get_nat(self.nat_type, self.port, self.interface, self.classifier_index, self.ip, self.priority))

    def get_nat_interface(self,nat_type,interface):
        self.__set_initial()
        self.nat_type = nat_type
        self.interface = interface
        self.__get_nat()

    def set_classiffer(self,classifier_index,classifier_ip_type,classifier_protocol_type,classifier_port_mode,classifier_port_no
                       ,classifier_ip_address):

        classifier_config = classifier(classifier_index)
        if classifier_ip_type =="protocol":
            classifier_config.get_protocol_classifier(classifier_ip_address,classifier_protocol_type,classifier_port_mode,classifier_ip_address)
        else:
            classifier_config.get_ip_classifier(classifier_ip_address)

        self.configlist.append(classifier_config.configlist)

    def get_nat_classiffer_ip(self,nat_type,interface,classifier_index,ip,priority):
        self.__set_initial()
        self.nat_type = nat_type
        self.interface = interface
        self.ip=ip
        self.__get_nat()

    def get_nat_classifier_port(self,nat_type,interface,classifier_index,ip,priority,port):
        self.__set_initial()
        self.nat_type = nat_type
        self.interface = interface
        self.classifier_index =classifier_index
        self.ip=ip
        self.port = port
        self.__get_nat()

if __name__ == '__main__':

    classifier_index = 100
    classifier_iptype ="protocol"
    classifier_protocol_type = "tcp"
    classifier_port_mode = "dport"
    classifier_port_no = 2222
    classifier_ip_address = "10.1.4.226"
    classifier_config = classifier(classifier_index)
    classifier_config.get_protocol_classifier(classifier_ip_address,classifier_protocol_type,classifier_port_mode,classifier_ip_address)
    print classifier_config.configlist


    nat_type = "dnat"
    nat_port = 22
    nat_interface = "maintenance 0"
    nat_interface_index = 0
    nat_classifier_index = 100
    nat_ip = "10.1.4.153"
    nat_priority = 1
    nat_config = nat()
    nat_config.set_classiffer(classifier_index,classifier_iptype,classifier_protocol_type,classifier_port_mode,classifier_port_no,classifier_ip_address)
    nat_config.get_nat_classifier_port(nat_type,nat_interface,classifier_index,nat_ip,nat_priority,nat_port)
    print nat_config.configlist




















