__author__ = 'ricky.wang'
import re
import httplib2
import json
import logging
from Device import *
from Tool import Log
import time
from time import gmtime, strftime

class ImageInfo(object):

    def __init__(self,host_ip="10.2.10.17",version="3.3"):
        self.hostip = host_ip
        self.version =version
        self.image_name = ""
        self.image_url_path = ""
        self.image_build_no =""
        self.imagelist = self.__string_with_num_sort(self._get_main_build_list(),True)

    def _get_html_content(self,url):
        httpUpgrade = httplib2.Http(disable_ssl_certificate_validation=True, timeout=5)
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        response, content =httpUpgrade.request(url, 'GET', headers=header)
        return content

    def _get_weekly_build_list(self):
        url = "http://%s/weekly/"%(self.hostip)
        htmlcontent = self._get_html_content(url)
        r = re.compile('<td>.*?<a .*?>(.*?)/</a>.*?</td>')
        Main_Build_List = r.findall(htmlcontent)
        return Main_Build_List

    def _get_main_build_list(self,version =''):
        if version == '': version = self.version
        url = "http://%s/weekly/v%s/"%(self.hostip,version)
        htmlcontent = self._get_html_content(url)
        r = re.compile('<td>.*?<a .*?_u_.*?\.img\">(.*?)</a>.*?</td>')
        Image_List =  r.findall(htmlcontent)
        return Image_List

    def get_host_image_list(self):
        imagedict={}
        itemlist = self._get_weekly_build_list()
        for item in itemlist:
            imagelist = sorted(self._get_main_build_list(item), reverse=True)

            if len(imagelist)>0 :
                  imagedict.setdefault(item,[]).append(imagelist)
        return imagedict

    def get_target_image(self,device_type,target_build_no):
        device_image_list = [a for a in self.imagelist  if device_type in a and 'vm' not in a]
        for image in device_image_list:
            if target_build_no in image:
                self.image_name = image
                self.image_url_path = u"http://%s/weekly/v%s/%s"%(self.hostip,self.version,self.image_name)
                self.image_build_no = image.split("_")[-1].replace(".img","")

        return self.image_name

    def get_last_image(self,device_type):
        image = ""
        device_image_list = [a for a in self.imagelist if device_type.lower() in a and 'vm' not in a]
        if len(device_image_list)>0:
            self.image_name = device_image_list[0]
            self.image_url_path = u"http://%s/weekly/v%s/%s"%(self.hostip,self.version,self.image_name)
            self.image_build_no =  self.image_name.split("_")[-1].replace(".img","")

        else:
            self.image_name =""
            self.image_url_path=""
            self.image_build_no=""
        return self.image_name



    def __string_with_num_sort(self,itemlist,IfReverse= True):
        convert = lambda text: int(text) if text.isdigit() else text.lower()
        alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
        return sorted(itemlist, key = alphanum_key,reverse=IfReverse)


class ImageTool(object):
    def __init__(self,device_ip,device_port,connect_type,username="admin",password="admin",logname="Image_Tool"):
        self.image_host_ip = ""
        self.image_version = ""
        self.image_url_path = ""
        self.update_image_url_path =""
        self.logname = logname
        self.logger = logging.getLogger('%s.Image'%(self.logname))
        self.device =  Device_Tool(device_ip,device_port,connect_type,username,password,logname)
        self.device.device_send_command("update terminal paging disable")
        self.device.device_get_version()


    def set_image_host(self,host_ip,image_version,image_mode,build_no):
        self.image_host_ip = host_ip
        self.image_version = image_version


         #get the imageinfo of updating
        imageinfo = ImageInfo(self.image_host_ip, self.image_version)
        if image_mode =="Target":
            imageinfo.get_target_image(self.device.device_type,build_no)
        else:
            imageinfo.get_last_image(self.device.device_type)
        print imageinfo.image_name
        self.update_build_image = "LileeOS_%s_%s"%(image_version,imageinfo.image_build_no)
        self.update_image_url_path =imageinfo.image_url_path


    def _set_default_config(self,interface,ip_mode,ipaddress,netmask):
        defaultcommandlist = list()
        defaultcommandlist.append("config security level permissive")
        if ip_mode == "static":
            defaultcommandlist.append("config interface %s ip address %s netmask %s"%(interface,ipaddress,netmask))
        elif ip_mode =="dhcp":
            defaultcommandlist.append("config interface %s ip address dhcp"%(interface))
        defaultcommandlist.append("config interface %s enable"%(interface))
        defaultcommandlist.append("save configuration")

        #set and check default config
        self.device.device_set_configs(defaultcommandlist)

    def _check_device_image(self,build_version):
        IF_Udate = True
        Check_Command = "show boot system-image"
        Check_Build = "Running: %s"%(build_version)
        result = self.device.device_send_command_match(Check_Command,10,Check_Build)
        self.logger.info("check_device_image Running: %s"%(result))

        if result == True:
            IF_Udate = False
        else:
            Check_Build = "Alternative image: %s"%(build_version)
            result = self.device.device_send_command_match(Check_Command,10,Check_Build)
            self.logger.info("check_rack_image Alternative: %s"%(result))
            if result == True:
                cmdresult = self.device.device_send_command("config boot system-image " + build_version)
                self.logger.info("check config boot system-image: %s"%(cmdresult))
                if cmdresult == True:
                        rebootresult = self.device.device_reboot()
                        self.logger.info("check rebootresult: %s"%(rebootresult))
                        if rebootresult == True:
                            self.logger.info('[Upgrade_Rack_Fw] login success to check rack running images')
                            Check_Build = "Running: %s"%(build_version)
                            result = self.device.device_send_command_match(Check_Command,10,Check_Build)
                            self.logger.info("check check_rack_image Running: %s"%(result))
                            if result == True:
                                IF_Udate = False
            else:
                IF_Udate = True

        return IF_Udate

    def _upgrade(self,pathFW,update_build_image):

        self.logger.info("[%s]udate devicet starting.."%(self.device.device_type))
        updatecmd = u"update boot system-image %s"%(pathFW)
        result = False
        download_match = "download"
        if "LMC" not in self.device.device_product_name:
            commandlist = [updatecmd,"yes"]
            resultlist = ["disk update","download"]
            result = self.device.device_send_multip_command_match(commandlist,20,resultlist)
        else:
            result = self.device.device_send_command_match(updatecmd,10,"downloaded")
        time.sleep(5)
        if result == True:
            self.logger.info("start to download to update image")
            timer_num = 0
            download_message = self.device.get_device_message()
            print download_message
            while download_match in download_message and timer_num <=300:
                time.sleep(5)
                download_message = self.device.get_device_message()
                timer_num +=1
                self.logger.info("[download image][%s] device message:%s"%(timer_num,download_message))

            timer_num = 0
            download_message = self.device.get_device_message()
            while 'localdomain' not in download_message and timer_num <=500:
                time.sleep(5)
                download_message = self.device.get_device_message()
                timer_num +=1
                self.logger.info("[wait to update][%s] device message:%s"%(timer_num,download_message))

        else:
            self.logger.error("[upgrade]fail:%s",self.device.target_response)

        IF_Udate = self._check_device_image(update_build_image)
        if IF_Udate ==False:
            return True
        else:
            return False

    def upgrade_device_image(self,maintain_interface,maintenance_ip_mode,maintenanceip,netmask):

        pingcommand ="ping -c5 %s"%(self.image_host_ip)
        pingresult = "64 bytes from %s: icmp_seq=5"%(self.image_host_ip)

        if self.update_image_url_path!="" :
            IF_Udate = self._check_device_image(self.update_build_image)
            self.logger.info('[upgrade_device_image] check if need to update:%s'%(IF_Udate))
            if IF_Udate ==True:
                    pingresult = self.device.device_send_command_match(pingcommand,10,pingresult)
                    if pingresult != True:
                        self.logger.info('[upgrade_device_image][ping fail]set default config')
                        self._set_default_config(maintain_interface,maintenance_ip_mode,maintenanceip,netmask)
                        time.sleep(10)
                        pingresult = self.device.device_send_command_match(pingcommand,10,pingresult)
                        if pingresult!=True:
                            self.logger.info('[upgrade_device_image][ping fail]start reboot')
                            rebootresult = self.device.device_reboot()
                            self.logger.info('[Upgrade_Device_Build_Image]reboot result:%s'%(rebootresult))
                            if rebootresult == True:
                                self.logger.info('[upgrade_device_image][after rebooting]set default config')
                                self._set_default_config(maintain_interface,maintenance_ip_mode,maintenanceip,netmask)
                                time.sleep(10)
                                pingresult = self.device_send_command_match(pingcommand,2,pingresult)
                                if pingresult ==True:
                                    self.logger.info("[upgrade_device_image]The image is the oldest one ,need to upgrade")
                                    upgraderesult = self._upgrade(self.update_image_url_path,self.update_build_image)
                                    self.logger.info("[upgrade_device_image]upgrade result:%s"%(upgraderesult))
                                else:
                                    self.logger.info('[upgrade_device_image][after rebooting]network had fail.')

                    else:
                        self.logger.info("[upgrade_device_image]The image is the oldest one ,need to upgrade")
                        upgraderesult = self._upgrade(self.update_image_url_path,self.update_build_image)
                        self.logger.info("[upgrade_device_image]upgrade result:%s"%(upgraderesult))

        else :
            self.logger.error( "Please choose new or target !!")


if __name__ == '__main__':
    mainlogger = Log("Image_Tool","Image_Tool")
    image_server = "10.2.10.17"
    imaage_version = '3.3'
    image_mode = 'Target'
    image_build_no ="62"
    deviceip = '10.2.11.58'
    deviceport = 2041
    device_connect_type = "telnet"
    username ="admin"
    password ="admin"

    item = list()
    maintain_interface ="maintenance 0"
    maintain_ip= '10.2.11.250'
    maintain_netmask ='255.255.252.0'
    maintaince_ip_mode ="static"
    imagetool =ImageTool(deviceip,deviceport,device_connect_type,username,password)
    imagetool.set_image_host(image_server,imaage_version,image_mode,image_build_no)
    imagetool.upgrade_device_image(maintain_interface,maintaince_ip_mode,maintain_ip,maintain_netmask)




