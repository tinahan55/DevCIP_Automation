class Profile(object):
    def __init__(self,type):
        self.type = type

    def get_cellular_profile(self,profile_name,access_name):
        commandlist = list()
        commandlist.append("create cellular-profile \"%s\""%(profile_name))
        commandlist.append("config cellular-profile \"%s\" access-point-name \"%s\""%(profile_name,access_name))
        return commandlist

    def get_wifi_profile(self,profile_name,ssid,key_type,wpa_version,wpa_key="",auth_type="",auth_eap_type=""
                         ,eap_username="",eap_key=""):
        commandlist = list()
        commandlist.append("create wifi-profile \"%s\""%(profile_name))
        commandlist.append("config wifi-profile \"%s\" ssid \"%s\""%(profile_name,ssid))
        if key_type !="":
            commandlist.append("config wifi-profile \"%s\" authentication key-management \"%s\""%(profile_name,key_type))
            commandlist.append("config wifi-profile \"%s\" authentication wpa-version \"%s\""%(profile_name,wpa_version))
            if key_type =="wpa-psk":
                commandlist.append("config wifi-profile \"%s\" authentication wpa-psk ascii \"%s\""%(profile_name,wpa_key))
            elif key_type =="wpa-eap":
                commandlist.append("config wifi-profile \"%s\" authentication %s type \"%s\""%(profile_name,auth_type,auth_eap_type))
                commandlist.append("config wifi-profile \"%s\" authentication eap-identity \"%s\""%(profile_name,eap_username))
                commandlist.append("config wifi-profile \"%s\" authentication eap-password \"%s\""%(profile_name,eap_key))

        return commandlist

class Interface(object):
    def __init__(self,type):
        self.type = type

    def get_dialer_interface(self,dialer_index,profile_name,cellular_index):
        commandlist = list()
        commandlist.append("config add interface dialer %s"%(dialer_index))
        commandlist.append("config interface dialer %s profile \"%s\""%(dialer_index,profile_name))
        commandlist.append("config interface dialer %s line cellular %s"%(dialer_index,cellular_index))
        commandlist.append("config interface dialer %s enable"%(dialer_index))
        return commandlist

    def get_wifi_interface(self,wifi_index,profile_name,wifi_mode,ip_mode,wifi_operating_mode,ipaddress,netmask):
        commandlist = list()
        commandlist.append("config add interface wlan %s %s"%(wifi_index,wifi_mode))
        commandlist.append("config interface wlan %s profile \"%s\""%(wifi_index,profile_name))
        if ip_mode =="static":
            commandlist.append("config interface wlan %s ip address %s netmask %s"%(wifi_index,ipaddress,netmask))
        elif ip_mode =="dhcp":
            commandlist.append("config interface wlan %s ip address dhcp"%(wifi_index))
        #config wifi operating mode (2.4g/5g/ac/auto)
        if wifi_operating_mode == "2.4g":
            commandlist.append("config interface wlan %s mode 2.4-ghz" %(wifi_index))
        elif wifi_operating_mode == "5g":
            commandlist.append("config interface wlan %s mode 5-ghz" %(wifi_index))
        elif wifi_operating_mode == "ac":
            commandlist.append("config interface wlan %s mode ac-mode" %(wifi_index))
        elif wifi_operating_mode == "auto":
            commandlist.append("config interface wlan %s mode auto" %(wifi_index))
        commandlist.append("config interface wlan %s enable"%(wifi_index))
        return commandlist

    def get_port_interface(self,port_index,port_type,vlan_index,vlan_tagged,port_tagged):
        commandlist = list()
        commandlist.append("config switch add vlan %s"%(vlan_index))
        if port_type == "app-engine":
            commandlist.append("config switch vlan %s add app-engine %s port 0"%(vlan_index,port_index))
            commandlist.append("config switch vlan %s app-engine %s port 0 egress %s"%(vlan_index,port_index,vlan_tagged))
        elif port_type =="port":
            commandlist.append("config switch vlan %s add port %s"%(vlan_index,port_index))
            commandlist.append("config switch vlan %s port %s egress %s"%(vlan_index,port_index,vlan_tagged))
            commandlist.append("config switch port %s default vlan %s"%(port_index,vlan_index))
            commandlist.append("config switch port %s egress %s"%(port_index,port_tagged))
        return commandlist

    def get_maintenance_interface(self,ip,netmask):
        commandlist = list()
        commandlist.append("config interface maintenance 0 ip address %s netmask %s"%(ip,netmask))
        commandlist.append("config interface maintenance 0 enable")
        return commandlist


class Function(object):
    def __init__(self,type):
        self.type = type


    def get_vlan(self,vlan_index,vlan_description,ip_mode,ipaddress,netmask):
        commandlist = list()
        commandlist.append("config add interface vlan %s"%(vlan_index))
        commandlist.append("config interface vlan %s description \"%s\""%(vlan_index,vlan_description))
        if ip_mode =="static":
            commandlist.append("config interface vlan %s ip address %s netmask %s"%(vlan_index,ipaddress,netmask))
        elif ip_mode =="dhcp":
            commandlist.append("config interface vlan %s ip address dhcp"%(vlan_index))
        commandlist.append("config interface vlan %s enable"%(vlan_index))
        return commandlist


       #for ip_type = destination or source or protocol
    def get_classifier(self,index,description,ip_type, protocol_type, port_mode, port_no,ip_address):
        commandlist = list()
        commandlist.append("config add classifier %s"%(index))
        if description!="":
            commandlist.append("config classifier %s description \"%s\""%(index,description))
        if ip_type == "protocol":
            if "port" in port_mode: # for tcp and udp + dport and sport
                commandlist.append("config classifier %s match ip protocol %s %s %s"%(index, protocol_type, port_mode, port_no))
            else: # for any and icmp
                commandlist.append("config classifier %s match ip protocol %s"%(index,protocol_type))
        else:
            commandlist.append("config classifier %s match ip %s %s"%(index,ip_type,ip_address))
        return commandlist


    def get_dhcp_pool(self, pool_name, pool_start_ip, pool_end_ip, pool_netmask, default_gateway):
        commandlist = list()
        commandlist.append("config add dhcp-pool \"%s\""%(pool_name))
        commandlist.append("config dhcp-pool \"%s\" add ip-address-range from %s to %s"%(pool_name, pool_start_ip, pool_end_ip))
        commandlist.append("config dhcp-pool \"%s\" netmask %s"%(pool_name, pool_netmask))
        commandlist.append("config dhcp-pool \"%s\" ip default-gateway %s"%(pool_name, default_gateway))
        return commandlist

    def set_dhcp_pool_dns(self,pool_name,dns_server_list,dns_priority_list):
        commandlist = list()
        for index,dns_server in enumerate(dns_server_list):
            dns_priority = dns_priority_list[index]
            commandlist.append("config dhcp-pool \"%s\" ip dns-server %s priority %s"%(pool_name, dns_server, dns_priority))
        return commandlist

    def set_dhcp_pool_interface(self,pool_name, dhcp_interface):
        commandlist = list()
        commandlist.append("config dhcp-server pool \"%s\" add interface %s"%(pool_name, dhcp_interface))
        return commandlist




    def get_nat(self, nat_type, port, interface, classifier_index, ip, priority):
        commandlist = list()
        if nat_type == "snat":
            if classifier_index != "":
                if port != "":
                    commandlist.append("config snat out-interface %s classifier %s translate-to ip %s port % priority %s"%(interface, classifier_index, ip, port, priority))
                else:
                    commandlist.append("config snat out-interface %s classifier %s translate-to ip %s priority %s"%(interface, classifier_index, ip, priority))
            else:
                commandlist.append("config snat out-interface %s priority %s"%(interface, priority))
        elif nat_type == "dnat":
            if classifier_index != "":
                if port != "":
                    commandlist.append("config dnat in-interface %s classifier %s translate-to ip %s port %s priority %s"%(interface, classifier_index, ip, port, priority))
                else:
                    commandlist.append("config dnat in-interface %s classifier %s translate-to ip %s priority %s"%(interface, classifier_index, ip, priority))
            else:
                if port != "":
                    commandlist.append("config dnat in-interface %s translate-to ip %s port % priority %s"%(interface, ip, port, priority))
                else:
                    commandlist.append("config dnat in-interface %s translate-to ip %s priority %s"%(interface, ip, priority))

        return commandlist

    def get_ntp(self,ntp_server_list,ntp_server_prority_list,time_source):
        commandlist = list()
        for index ,value in enumerate(ntp_server_list):
            prority =  ntp_server_prority_list[index]
            commandlist.append("config ntp server %s priority %s"%(value, prority))
        commandlist.append("config ntp time-source %s"%(time_source))

        return commandlist

    def get_service(self,service_name):
        commandlist = list()
        commandlist.append("config service %s enable"%(service_name))
        return commandlist

    def get_user(self,user_name,user_password_secret_key,user_role='user'):
        commandlist = list()
        commandlist.append("config add user %s password %s"%(user_name,user_password_secret_key))
        if user_role!="user":
            commandlist.append("config user %s role %s"%(user_name,user_role))
        return commandlist

    def get_route(self, route_type, route_mode, route_ip, route_netmask, gateway, interface, metric, table_index, default_interface):
        commandlist =list()
        if route_type == "ip":
            if route_mode == "network":
                if gateway !="" and interface!="":
                    commandlist.append("config route ip network %s netmask %s gateway %s interface  %s"%(route_ip, route_netmask, gateway,interface))

                elif gateway != "":
                    commandlist.append("config route ip network %s netmask %s gateway %s"%(route_ip, route_netmask, gateway))
                elif interface != "":
                    commandlist.append("config route ip network %s netmask %s interface %s" % (route_ip, route_netmask, interface))
                else:
                    commandlist.append("config route ip network %s %s"%(route_ip, route_netmask))
            else:
                if interface != "":
                    commandlist.append("config route ip default gateway %s interface %s metric %s"%(gateway, interface, metric))
                else:
                    commandlist.append("config route ip default gateway %s"%(gateway))

        elif route_type == "table":
            if route_mode == "network":
                commandlist.append("config route table %s ip network %s %s"%(table_index, route_ip, route_netmask))
            else:
                commandlist.append("config route table %s ip default interface %s"%(table_index, default_interface))

        return commandlist


    def get_policy_route(self,classifier_index, table_index,priority):
        commandlist = list()
        commandlist.append("config policy-route classifier %s table %s priority %s" % (classifier_index, table_index, priority))

        return commandlist
    def get_tunnel(self, device_type, threading_mode,tunnel_mode, interface, mobility_controller, controller_ip):
        cmdlist = list()
        cmdlist.append("config mobility type layer-2") # This command is default value for LileeOS
        cmdlist.append("config mobility mode %s" % (tunnel_mode))  # Look udp mode is default value for LileeOS
        if device_type == "lmc":
            if threading_mode == "performance":
                cmdlist.append("config mobility performance cpu-spec enable")
            # commandlist.append("config mobility bridge interface eth4 vlan-access %s"%(interface))
        else:
            cmdlist.append("config mobility uplink interface %s controller %s" % (interface, controller_ip))
            if mobility_controller != "":
                cmdlist.append("config host mobility-controller %s" % (mobility_controller))

        return cmdlist


class WifiProfile(object):
    def __init__(self,radius_host_ip="10.2.11.44",auth_port="1812",acct_port="1813",auth_key="LileeSystems",acct_key="LileeSystems",eap_id= "lance",eap_pwd= "lance0124",eap_tls_id="lancewei124@gmail.com",ca_cert="ca.pem",client_cert="client.pem",pri_key="client.p12",pri_pwd="whatever"):
        #self.mode = mode
        #self.auth_type = auth_type
        self.radius_host_ip = radius_host_ip
        self.auth_port = auth_port
        self.acct_port = acct_port
        self.auth_key = auth_key
        self.acct_key = acct_key
        self.eap_id = eap_id
        self.eap_pwd = eap_pwd
        self.eap_tls_id = eap_tls_id
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.pri_key = pri_key
        self.pri_pwd = pri_pwd

    def get_wificonfig_open(self,mode,profile_name,ssid):
        commandlist = list()
        commandlist.append("create wifi-profile %s" % (profile_name))
        commandlist.append("config wifi-profile %s ssid %s" % (profile_name, ssid))
        commandlist.append("config wifi-profile %s authentication open" % (profile_name))
        return commandlist

    def get_wificonfig_wpa_psk(self,mode,profile_name,ssid,wpa_version,wpa_key):
        commandlist = list()
        commandlist.append("create wifi-profile \"%s\"" % (profile_name))
        commandlist.append("config wifi-profile \"%s\" ssid \"%s\"" % (profile_name, ssid))
        commandlist.append("config wifi-profile \"%s\" authentication key-management wpa-psk" % (profile_name))
        if mode == "ap":
            commandlist.append("config wifi-profile \"%s\" authentication wpa-version \"%s\"" % (profile_name,wpa_version))
            commandlist.append("config wifi-profile \"%s\" authentication wpa-psk ascii \"%s\"" % (profile_name,wpa_key))
        else:
            commandlist.append("config wifi-profile \"%s\" authentication wpa-version \"%s\"" % (profile_name, wpa_version))
            commandlist.append("config wifi-profile \"%s\" authentication wpa-psk ascii \"%s\"" % (profile_name, wpa_key))
        return commandlist

    def get_wificonfig_eap(self,mode,profile_name,ssid,wpa_version,eap_type):
        #radius_host_ip = self.radius_host_ip
        radius_host_ip = "10.2.11.44"
        auth_port = self.auth_port
        acct_port = self.acct_port
        auth_key = self.auth_key
        acct_key = self.acct_key
        eap_id = self.eap_id
        eap_pwd = self.eap_pwd
        eap_tls_id = self.eap_tls_id
        ca_cert = self.ca_cert
        client_cert = self.client_cert
        pri_key = self.pri_key
        pri_pwd = self.pri_pwd

        commandlist = list()
        commandlist.append("create wifi-profile \"%s\"" % (profile_name))
        commandlist.append("config wifi-profile \"%s\" ssid \"%s\"" % (profile_name, ssid))
        commandlist.append("config wifi-profile \"%s\" authentication key-management wpa-eap" % (profile_name))
        if mode == "ap":
            commandlist.append("config wifi-profile \"%s\" authentication wpa-version \"%s\"" % (profile_name, wpa_version))
            commandlist.append("config wifi-profile \"%s\" radius auth-server host \"%s\" port \"%s\" key \"%s\"" % (profile_name, radius_host_ip, auth_port, auth_key))
            #commandlist.append("config wifi-profile %s radius auth-server host %s port %s key %s" % (profile_name, radius_host_ip, auth_port, auth_key))
            commandlist.append("config wifi-profile \"%s\" radius acct-server host \"%s\" port \"%s\" key \"%s\"" % (profile_name, radius_host_ip, acct_port, acct_key))
            #commandlist.append("config wifi-profile %s radius acct-server host %s port %s key %s" % (profile_name, radius_host_ip, acct_port, acct_key))
        else:
            if eap_type == "peap":
                commandlist.append("config wifi-profile \"%s\" authentication sta-eap type peap" % (profile_name))
                commandlist.append("config wifi-profile \"%s\" authentication eap-identity \"%s\"" % (profile_name, eap_id))
                commandlist.append("config wifi-profile \"%s\" authentication eap-password \"%s\"" % (profile_name, eap_pwd))
            else:
                commandlist.append("config wifi-profile \"%s\" authentication sta-eap type tls" % (profile_name))
                commandlist.append("config wifi-profile \"%s\" authentication eap-identity \"%s\"" % (profile_name, eap_tls_id))
                commandlist.append("config wifi-profile \"%s\" authentication ca-certificate filename \"%s\"" % (profile_name, ca_cert))
                commandlist.append("config wifi-profile \"%s\" authentication client-certificate filename  \"%s\"" % (profile_name, client_cert))
                commandlist.append("config wifi-profile \"%s\" authentication private-key filename \"%s\" password %s" % (profile_name, pri_key, pri_pwd))
        return commandlist




























































