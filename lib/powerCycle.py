'''
Created on 2015

@author: joey.chan
'''


import os
import sys
import io
import codecs
import time
import string
import struct
import httplib
import httplib2
import urllib
import urllib2
import cookielib
import re


class powerCycle:
    
    #power cycle device
    #parameter: relay ip, user name, password, device name
    def powerControl(self, ip, userName, passwd, devName):
        self.http = httplib2.Http(disable_ssl_certificate_validation=True, timeout=5)
        #self.http = httplib2.Http(timeout=5)
        self.ipAddr = "http://" + ip
        self.url = "http://" + ip + "/login.tgi"
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'Username':userName, 'Password':passwd}
        data = urllib.urlencode(data)
        indexPage = "http://" + ip +"/index.htm"
        devCheck = False 
        
        #login power control web
        response, content = self.http.request(self.url, 'POST', headers=header, body=data)
        header = {'Cookie': response['set-cookie']}
        print header
        response, self.content = self.http.request(indexPage, 'GET', headers=header)
        #print response
        #print self.content
        if int(str(self.content).find("Ethernet Power Controller")) > 0 :
            print "Login power control successful"

        else :
            print "Login power control fail"
            return "fail"


        #parse device information
        tableTmp = re.findall(r'individual control table.*?([^*]*)/individual control table', str(self.content))
        #print tableTmp
        
        
        devTable = re.findall(r'<td>([^>]*)</td>', str(tableTmp))
        devLink = re.findall(r'<a  href=([^>]*)>Cycle', str(tableTmp))
        for i in range(0, len(devTable), 1) :
            #print devTable[i]
            #print "link= " + devLink[i]
            if str(devTable[i]) == devName :
                print devTable[i]
                print devLink[i]
                print "request => " + self.ipAddr + "/" + str(devLink[i])
                response, content = self.http.request(self.ipAddr + "/" + str(devLink[i]) , 'GET', headers=header)
                print response
                status = re.findall(r'status.*?: \'([^>]+?)\'', str(response))
                status = str(status).replace("['", "")
                status = str(status).replace("']", "")
                if status == "200" :                    
                    print "power cycle successful"
                    devCheck = True
                    return "success"
                
        if devCheck != True :
            print "Not find device"
            return "fail"
        return devCheck


if __name__ == '__main__':
    test3 = powerCycle()
    test3.powerControl("10.2.66.56", "admin", "lilee1234", "Outlet 7 DTS1")
