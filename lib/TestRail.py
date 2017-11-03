from thirdparty.testrail import *
import logging
import os
from time import gmtime, strftime
from Tool import Log
import sys
import requests



class RackResult(object):

    def __init__(self,rack,tcid,origintcid,devicetype,result,groupid):
        self.rack =rack
        self.tcid = tcid
        self.origintcid = origintcid
        self.devicetype = devicetype
        self.result = result
        self.groupid =groupid


class TestRailRunCase(object):

    def __init__(self,runid,caseid,config,tcid):
        self.runid = runid
        self.caseid = caseid
        self.config = config
        self.tcid =tcid


class RackTestReport(object):

    def __init__(self,apiaddress):
     self.apiip = apiaddress

    def get_test_report(self,rackname,week):
        payload = {'rack': rackname,'week':week}
        url = self.apiip+"/reports"
        r = requests.get(url, params=payload)
        return r.json()

    def get_device_name(self,index):
        devicename ='LMC'
        if index =='0':
            devicename='LMC'
        elif index=='2':
            devicename='DTS'
        elif index=='4':
            devicename='LMS'

        return devicename

class TestRailAPI(object):
    def __init__(self,host='https://lileesystems.testrail.net',user = "sqa.testrail@lileesystems.com",password = "5tgb^YHN"
                 ,logname=""):
        self.client = APIClient(host)
        self.client.user =user
        self.client.password=password
        self.logger = logging.getLogger('%s.testailapi'%(logname))
        self.logger.info('creating the sub log for testrailapi')

    def get_project_list(self):
        url ='get_projects'
        projectlist = self.client.send_get(url)
        return projectlist

    def get_test_plan(self,project_id):
        url = 'get_plans/%s'%(project_id)
        planlist = self.client.send_get(url)
        return planlist


    def get_test_plan_detail(self,plan_id):
        url = 'get_plan/%s'%(plan_id)
        detail = self.client.send_get(url)
        return detail

    def __get_test_run(self,run_id):
        url='get_run/%s'%(run_id)
        run =self.client.send_get(url)
        print run


    def __get_tests(self,run_id):
        url='get_tests/%s'%(run_id)
        tests = self.client.send_get(url)
        return tests



    def get_test_case(self,project_id,suite_id,section_id=None):
        url = 'get_cases/%s&suite_id=%s'%(project_id,suite_id)
        if section_id !=None:
            url = "&section_id=%s"%(section_id)
        caselist = self.client.send_get(url)
        return caselist

    def get_test_case_detail(self,case_id):
        url = 'get_case/%s'%(case_id)
        case = self.client.send_get(url)
        return case

    def get_status_name(self,status_name):
        status_id =1
        if status_name == "PASS":
            status_id = 1
        elif status_name =="FAIL":
            status_id =5
        elif status_name=="N/A":
            status_id=5
        return status_id


    def get_results_for_case(self,run_id,case_id):
        url ='get_results_for_case/%s/%s'%(run_id,case_id)
        result =  self.client.send_get(url)
        return result

    def __get_results_for_test(self,test_id):
        url ='get_results/%s'%(test_id)
        result =  self.client.send_get(url)
        return result



    def add_result_for_case(self,run_id,case_id,status_id,build_version,comment):
        url ='add_result_for_case/%s/%s'%(run_id,case_id)
        data ={"status_id":status_id,"version":build_version,"comment":comment,"defects":""}
        result = self.client.send_post(url,data)
        if "200" in result:
            return True
        else:
            return False
    def __add_result_for_test(self,test_id,status_id,build_version,comment):
        url ='add_result/%s'%(test_id)
        data ={"status_id":status_id,"version":build_version,"comment":comment,"elapsed":"","defects":""}
        result = self.client.send_post(url,data)
        if result["test_id"]== test_id:
            return True
        else:
            return False

    def __get_result_status_id(self,result_status):
        status_id =1
        if result_status == "PASS":
            status_id = 1
        elif result_status =="FAIL":
            status_id =5
        elif result_status=="N/A":
            status_id=5
        return status_id


    def __update_result(self,test_id,status_id,buildversion,comment,ifwriteable):
        try:
            resultlist = self.__get_results_for_test(test_id)
            filter_result =  list(railresult for railresult in resultlist if railresult["version"] == buildversion)
            if len(filter_result) == 0:
                try:
                    self.logger.info("[update_result]not result for this build")
                    add_result =  self.__add_result_for_test(test_id,status_id,buildversion,comment)
                    self.logger.info("[update_result] result: %s"%(add_result))
                    return  add_result

                except Exception,ex:
                    self.logger.error("[add result] result: Fail:(%s)"%(str(ex)))
                    return False
            else:
                if ifwriteable == True:
                    self.logger.info("[update_result]update result for this build again.")
                    add_result =  self.__add_result_for_test(test_id,status_id,buildversion,comment)
                    self.logger.info("[update_result] result: %s"%(add_result))
                    return  add_result

        except Exception,ex:
            self.logger.error("[update_result] result: Fail:(%s)"%(str(ex)))
            return False


    def update_test_result(self,project_name,test_plan,test_run,device_type,case_id,build_version,result,comment,ifwriteable):
        update_result = False
        self.logger.info("[update_test_result] %s,%s,%s,%s,%s,%s,%s,%s,%s"%(project_name,test_plan,test_run,device_type,case_id,build_version,result,comment,ifwriteable))
        projectlist = self.get_project_list()
        filterproject =  list(project for project in projectlist if project["name"] == project_name)
        if filterproject!=None:
            project_id = filterproject[0]["id"]
            planlist = self.get_test_plan(project_id)
            filterplan =  list(plan for plan in planlist if plan["name"] == test_plan)
            if filterplan!=None:
                plan_id = filterplan[0]["id"]
                detail = self.get_test_plan_detail(plan_id)
                entity = list(entity for entity in detail["entries"] if entity["name"] == test_run)
                if entity!=None:
                    run = list(run for run in entity[0]["runs"] if run["config"] == device_type.upper())
                    print run
                    if run!=None:
                        run_id = run[0]["id"]
                        testlist = self.__get_tests(run_id)
                        test = list(test for test in testlist if test["case_id"] == case_id)
                        if test!=None:
                            status_id = self.__get_result_status_id(result)
                            case_id = test[0]["case_id"]
                            test_id = test[0]["id"]
                            print "%s,%s"%(case_id,test_id)
                            update_result = self.__update_result(test_id,status_id,build_version,comment,ifwriteable)
                            self.logger.info("[update_test_result] result : %s"%(update_result))


            return update_result


def get_testrail_case_list(testrailapi,projectname,planname):
    runcaselist = list()
    projectlist = testrailapi.get_project_list()
    filterproject =  (project for project in projectlist if project["name"] == projectname)
    for project in filterproject:
        if project["name"] == projectname:
            print "ProjectID :%s , %s"%(project["id"],project["name"])
            planlist = testrailapi.get_test_plan(project["id"])
            filterplan =  (plan for plan in planlist if plan["name"] == planname)
            for plan in filterplan:
                detail = testrailapi.get_test_plan_detail(plan["id"])
                for entity in  detail["entries"]:
                    for run in entity["runs"]:
                        caselist = testrailapi.get_test_case(run["project_id"],run["suite_id"])
                        for case in caselist:
                            try:
                                runcase =TestRailRunCase(str(run["id"]), str(case["id"]),str(run["config"]),str(case["custom_caseid"]))
                                runcaselist.append(runcase)
                            except Exception, e:
                                print case["title"]
    return runcaselist


def get_testrack_result_list(apiurl,rack,week):
    rackresultlist = list()
    racktestreport = RackTestReport(apiurl)
    rackname = "testrack%s.device.config"%(rack)
    testreport = racktestreport.get_test_report(rackname,week)
    for item in testreport:
        tcid = item["tcid"]
        groupid = item["groupid"]
        testresult = item["result"]
        deviceindex = tcid[0]
        devicetypename = racktestreport.get_device_name(deviceindex)
        newtcid ='X' + tcid[1:]
        rackresultlist.append(RackResult(rack,newtcid,tcid,devicetypename,testresult,groupid))
    return rackresultlist


def update_testrail_result_bygroup(testrailapi,rackresultlist,buildversion,groupid,result):
    comment = "Auto Upload"
    filterracklist = (rackresult for rackresult in rackresultlist if rackresult.groupid== groupid)
    for rackresult in filterracklist:
        add_flag = False
        if result!="All":
            if rackresult.result == result:
                add_flag = True
            else:
                print "[existed-result is not matched][%s]rack:%s ,oldtcid: %s ,newtcid : %s ,devicetypename : %s,result : %s"%(rackresult.groupid,rackresult.rack,rackresult.origintcid,rackresult.tcid,rackresult.devicetype,rackresult.result)

        else:
            add_flag = True

        if add_flag == True:
            status_id = testrailapi.get_status_name(rackresult.result)
            filter_case = filter(lambda x: x.tcid == rackresult.tcid and x.config == rackresult.devicetype , runcaselist)
            if(len(filter_case)>0):
                print "[existed][%s]rack:%s ,oldtcid: %s ,newtcid : %s ,devicetypename : %s,result : %s"%(rackresult.groupid,rackresult.rack,rackresult.origintcid,rackresult.tcid,rackresult.devicetype,rackresult.result)
                runid = filter_case[0].runid
                caseid =filter_case[0].caseid
                print "[existed][%s]rack:%s ,oldtcid: %s ,newtcid : %s ,devicetypename : %s,result : %s"%(rackresult.groupid,rackresult.rack,rackresult.origintcid,rackresult.tcid,rackresult.devicetype,rackresult.result)
                add_result(runid,caseid,status_id,buildversion,comment)

            else:
                print "[no existed case in test plan][%s]rack:%s ,oldtcid: %s ,newtcid : %s ,devicetypename : %s,result : %s"%(rackresult.groupid,rackresult.rack,rackresult.origintcid,rackresult.tcid,rackresult.devicetype,rackresult.result)

def add_result(runid,caseid,status_id,buildversion,comment):
    try:
        testrailapi = TestRailAPI()
        resultlist = testrailapi.get_results_for_case(runid,caseid)
        filter_result =  list(railresult for railresult in resultlist if railresult["version"] == buildversion)
        if len(filter_result) == 0:
            try:
                print "not result for this build"
                add_result = testrailapi.add_result_for_case(runid,caseid,status_id,buildversion,comment)
                if (add_result):
                    print "[add result] result: Completed."
            except Exception,ex:
                print "[add result] result: Fail:(%s)"%(str(ex))
        else:
            print "[exist] result had been existed, not need to upload:%s"%(str(len(filter_result)))

    except Exception,ex:
            print "[get result] result: Fail:(%s)"%(str(ex))


if __name__ == '__main__':
    mainlogger = Log("TestrailLog","main")
    projectname = "LileeOS"
    runversion ="3.5"
    buildid = "20"
    week ="WR40"
    planname = "LileeOS 3.5.2 New&Manual Test"
    result = "PASS"
    rack_group = "4_ATS28FR_Group1282:7_Group1280:8_Group1281_Group2281_Group3281"
    apiurl = "http://10.2.10.191:8080/api"
    testrailusername = "sqa.testrail@lileesystems.com"
    testrailpassword = "5tgb^YHN"
    racklist =list()
    groupidlist = list()
    if len(sys.argv)>3:
        ## initial paramter
        projectname = sys.argv[1]
        runversion = sys.argv[2]
        buildid =sys.argv[3]
        week = sys.argv[4]
        planname = sys.argv[5]
        result = sys.argv[6]
        testrailusername = sys.argv[7]
        testrailpassword = sys.argv[8]
        rack_group = sys.argv[9]

    testrailapi = TestRailAPI(user = testrailusername,password=testrailpassword)
    buildversion = "%s_build%s"%(runversion,buildid)

    # parsing the rack info
    if ':' in rack_group:
        rackinfo = rack_group.split(":")
        for rack in rackinfo:
            if '_' in rack:
                rackitem = rack.split("_")
                for index,value in enumerate(rackitem):
                    if index == 0:
                        racklist.append(value)
                    else:
                       groupidlist.append(value)
    else:
        rackitem = rack_group.split("_")
        for index,value in enumerate(rackitem):
            if index == 0:
                racklist.append(value)
            else:
                groupidlist.append(value)

    runcaselist = get_testrail_case_list(testrailapi,projectname,planname)
    if len(runcaselist)>0:
        for rack in racklist:
            rackresultlist = get_testrack_result_list(apiurl,rack,week)
            if len(rackresultlist) > 0:
                for groupid in groupidlist:
                    update_testrail_result_bygroup(testrailapi,rackresultlist,buildversion,groupid,result)
    '''

    project_name ="ATS_Test"
    test_plan = "test1"
    test_run = "PreTesting"
    comment = "Auto result upload"
    device_type = "STS"
    test_id = 11907
    buildversion = "3.3_build60"
    result ="Passed"
    comment = "Auto test passed"
    testrail =TestRailAPI(logname="main")
    result = testrail.update_test_result(project_name,test_plan,test_run,device_type,test_id,buildversion,result,comment,True)
    mainlogger.write("info",result)

    '''
