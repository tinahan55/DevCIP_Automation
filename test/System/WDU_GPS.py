from lib.Device import *
from lib.Configuration import *
from lib.powerCycle import *
import logging
import os
from time import gmtime, strftime
import requests
import websocket
from datetime import datetime,timedelta
from json import JSONEncoder
import time


class RequestParam:
    def __init__(self,asset_name,rev,method,post_data,request,expire,timer):
        self.asset_name=asset_name
        self.rev=rev
        self.method=method
        self.post_data = post_data
        self.request = request
        self.expire = int(expire)
        self.timer= int(timer)

class ClientSocket(object):
    ClientID = 0
    Count = 1
    Times = 0
    cookie=""

    def __init__(self,server_ip,device,cookie,wait_times,logger):
        self.server_ip = server_ip
        self.cookie = cookie
        self.device = device
        self.server_ip =server_ip
        self.initial_times =1
        self.wait_times = wait_times
        self.gps_result = False
        self.logger = logger

    def on_message(self,ws, message):
            if message =="":
                self.logger.info("[websocket]The device did not connect to lmc.")
            else:
                 if "gps" in message and self.initial_times< self.wait_times:
                    try:
                        decoded = json.loads(message)
                        gps = decoded['respond']['reps'][6]['union']['gps']
                        longitude =  int(gps['longitude'])
                        latitude = int(gps['latitude'])
                        output = "[websocket][%s]gps:  longitude %s - latitude:%s , " % (self.Count,gps['longitude'],gps['latitude'])
                        self.logger.info(output)
                        if longitude > 0 and latitude>0:
                            self.gps_result =True
                            self.ws.close()
                        else:
                            self.logger.info("[websocket][%s]The device did not get gps data from lmc.:%s"%(self.Count,message))
                            self.initial_times +=1


                    except Exception ,ex :
                        self.logger.error("message parsing error message:"+ message)
                        self.initial_times +=1
                 if self.initial_times> self.wait_times:
                     self.gps_result=False
                     self.ws.close()
    def on_error(self,ws, error):
        print error

    def on_close(self,ws):
        print 'close'
        logging.debug(self.device.asset_name+":disconnected streaming server")

    def on_open(self,ws):
        print 'open'
        self.ws.send(MyEncoder().encode(self.device))

    def do_action(self):
        try:
            self.initial_times=1
            self.gps_result =False
            websocket.enableTrace(True)
            self.ws = websocket.WebSocketApp("ws://"+self.server_ip +"/app_gateway/socket",
            on_message = self.on_message,
            on_error = self.on_error,
            on_close = self.on_close,
            cookie=  self.cookie)
            self.ws.on_open = self.on_open
            self.ws.run_forever()
        except KeyboardInterrupt,e:
            logging.debug(str(e))
            self.ws.close()


class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

def get_authcookie(host,headers,payload):
     session = requests.Session()
     resp = session.post(host, data=payload, headers=headers, allow_redirects=True)
     cookie ="AuthByLilee="+session.cookies.get_dict()["AuthByLilee"]+"; path=/;"
     return cookie

def get_cookie_from_server(serverip,username,passwd):
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    payload = {'username': username, 'passwd': passwd,"url": '/nms/'}
    AuthUrl = "http://"+serverip+"/login/auth.cgi"
    return get_authcookie(AuthUrl,headers,payload)

def set_log(filename,loggername):
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

if __name__ == '__main__':
    logfilename = "WDU_GPS_Testing%s.log"%(strftime("%Y%m%d%H%M", gmtime()))
    logger = set_log(logfilename,"WDU_GPS_Testing")

    # device_info
    device_ip ="10.2.53.150"
    device_port = 22
    device_connect_mode ="ssh"
    device_username = "admin"
    device_password ="admin"


    #lmc_info
    server_ip = "10.2.53.203"
    server_port = 22
    server_connect_mode ="ssh"
    server_username = "admin"
    server_password ="Lilee1234"


    # Power Server
    din_relay_ip = '10.2.53.199'
    din_relay_user ="root"
    din_relay_pwd ="lilee1234"
    din_relay_index = 2
    din_relay_cmd ="CCL"

    #command_info
    device_name ="SQA-LMS-WDU"
    build_version = "3.4"
    method = "GET"
    command = "statistic/report"
    expired = 5
    timer =10

    #condition_info
    cycle_times = 200
    Wait_GPS_Times = 30
    end_uptime=240

    if len(sys.argv)>3:
        device_info =sys.argv[1].split("_") #ssh_10.2.53.253_22_admin_admin
        lmc_info = sys.argv[2].split("_") #ssh_10.2.53.203_22_admin_Lilee1234
        din_server_info = sys.argv[3].split("_")#10.2.53.199_root_lilee1234_2_CCL
        command_info = sys.argv[4].split("_") #SQA-Ricky-WDU_3.4_GET_statistic/report_5_10
        condition_info =sys.argv[5].split("_")#200_30_240


        # device_info
        device_connect_mode = device_info[0]
        device_ip = device_info[1]
        device_port = device_info[2]
        device_username = device_info[3]
        device_password = device_info[4]

         #lmc_info
        server_connect_mode =lmc_info[0]
        server_ip = lmc_info[1]
        server_port = lmc_info[2]
        server_username = lmc_info[3]
        server_password = lmc_info[4]

        # Power Server
        din_relay_ip = din_server_info[0]
        din_relay_user =din_server_info[1]
        din_relay_pwd =din_server_info[2]
        din_relay_index = din_server_info[3]
        din_relay_cmd =din_server_info[4]

        #command_info
        device_name =command_info[0]
        build_version = command_info[1]
        method =command_info[2]
        command = command_info[3]
        expired = int(command_info[4])
        timer =int(command_info[5])


        #condition_info
        cycle_times = int(condition_info[0])
        Wait_GPS_Times = int(condition_info[1])
        end_uptime=int(condition_info[2])


    pass_count = 0
    result_fail_count = 0
    respond_fail_count = 0
    powerCycle = powerCycle()
    cookies =get_cookie_from_server(server_ip,server_username,server_password)
    request_device = RequestParam(device_name,build_version,method,"",command,expired,timer)
    client = ClientSocket(server_ip,request_device,cookies,Wait_GPS_Times,logger)

    device =Device_Tool(device_ip,device_port,device_connect_mode,device_username,device_password,"WDU_GPS_Testing")
    if device:
        device.device_send_command("update terminal paging disable",10)
        device.device_get_version()
        device.device_get_hostname()
        device.device_get_register_MAC("maintenance 0")
        logger.info("Server Device type:%s"%(device.device_type))
        logger.info("Server Device Bios Version:%s"%(device.bios_version))
        logger.info("Server Device recovery image:%s"%(device.boot_image))
        logger.info("Server Device build image:%s"%(device.build_image))
        logger.info("Server Device testrail image:%s"%(device.testrail_build_version))
        logger.info("Server Device mac:%s"%(device.device_register_MAC))
        logger.info("Server Device hostname:%s"%(device.device_hostname))
        logger.info("Server Device version:%s"%(device.branch_version))
        for k in range(0, cycle_times):
            power_cycle_result =powerCycle.powercontrolbyIndex(din_relay_ip, din_relay_user, din_relay_pwd, din_relay_index,din_relay_cmd )
            logger.info("[%s][power_cycle_result]result :%s"%(k,power_cycle_result))
            if power_cycle_result:
                start_time = datetime.now()
                logger.info("Start to Wait for booting and then to check the gps data and calculate time.")
                client.do_action()
                end_time =datetime.now()
                total_wait_second = (end_time-start_time).total_seconds()
                logger.info("[Check gps result]: total_second: %s , data result :%s"%(total_wait_second,client.gps_result))
                if total_wait_second> end_uptime :
                    respond_fail_count+=1
                else:
                    if client.gps_result ==False:
                        result_fail_count+=1
                    else:
                        pass_count+=1

            logger.info("[Total Result][%s]: Pass Count:%s , Result Fail Count:%s , Respond Fail Count:%s"%(k,pass_count,result_fail_count,respond_fail_count))

                    #checkresult = device.device_send_command_match("show gps detail",5,"Fix Quality : 3D ")
                    #logger.info("%s check %s result :%s"%("Check gps status","show gps detail",checkresult))
                    #logger.info("%s check %s error :%s"%("Check gps status","show gps detail",device.target_response))
                    #time.sleep(1)
