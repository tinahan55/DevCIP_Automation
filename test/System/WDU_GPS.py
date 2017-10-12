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

    def __init__(self,server_ip,device,cookie,times,logger):
        self.server_ip = server_ip
        self.cookie = cookie
        self.device = device
        self.server_ip =server_ip
        self.wait_times =times
        self.gps_result = False
        self.logger = logger

    def on_message(self,ws, message):

        if self.Count < self.wait_times:
            if message =="":
                self.logger.info("[websocket]The device did not connect to lmc.")
            else:
                if "gps" in message:
                    try:
                        decoded = json.loads(message)
                        gps = decoded['respond']['reps'][2]['union']['gps']
                        longitude =  int(gps['longitude'])
                        latitude = int(gps['latitude'])
                        output = "[websocket][%s]gps:  longitude %s - latitude:%s , " % (self.Count,gps['longitude'],gps['latitude'])
                        self.logger.info(output)
                        if longitude > 0 and latitude>0:
                            self.gps_result =True
                            self.ws.close()
                        else:
                            self.logger.info("[websocket][%s]The device did not get gps data from lmc.:%s"%(self.Count,message))
                    except Exception ,ex :
                        logger.error(str(ex)+":"+ message)

        else:
            self.ws.close()



            self.Count+=1
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
            self.Count=0
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

    # Device Information
    device_ip ="10.2.53.253"
    device_port = 22
    device_connect_mode ="ssh"
    device_username = "admin"
    device_password ="admin"
    device_name ="SQA-Ricky-WDU"

    # Power Server
    din_relay_ip = '10.2.53.199'
    din_relay_user ="root"
    din_relay_pwd ="lilee1234"
    din_relay_index = 2
    din_relay_cmd ="CCL"


    cycle_times = 200
    serverip = "10.2.53.203"
    powerCycle = powerCycle()
    cookies =get_cookie_from_server(serverip,"admin","Lilee1234")
    request_device = RequestParam(device_name,"3.4","GET","","statistic/report",5,10)
    WaitTimes = 180
    pass_count = 0
    result_fail_count = 0
    respond_fail_count = 0
    client = ClientSocket(serverip,request_device,cookies,WaitTimes,logger)
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
                if total_wait_second> 180 :
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
