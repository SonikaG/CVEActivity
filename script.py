import mysql.connector
import nvdlib
import datetime
from packaging.version import Version
import sys

from config import *

def create_database(end, last_date, keyword_string):
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=30)
    last_date = datetime.datetime(2023, 1, 1)
    cpes = []
    while(start > last_date):
        print("in loop")
        cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=start, lastModEndDate=end))
        start -= datetime.timedelta(days=30)
        end -= datetime.timedelta(days=30) 
    cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=last_date, lastModEndDate=end))
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cpes = set(cpes)
    print(len(cpes))
    cves = {}
    for cpe in cpes: 
        #print(cpe.cpeName)
        print("in second loop")
        version = cpe.cpeName.split(":")[5]
        if (containsDigit(version)):
            version = Version(version)
        else:
            version = None
        timestamp = cpe.lastModified
        results = set(nvdlib.searchCVE(cpeName = cpe.cpeName))
        for cve in results: 
            if cve.id not in cves: 
                versions = []
                if version: 
                    versions.append(version)
                cves[cve.id] = versions
            else:
                '''#see if timestamp is sooner
                if timestamp > cves[cve.id].timestamp:
                    cves[cve.id].timestamp = timestamp'''
                #update version numbers
                if version:
                    cves[cve.id].append(version)
    print(list(cves.items()))
    create_database_mysql(cves, current_time)



def create_database_mysql(cves, current_time,tableName):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE " +  tableName + " (ID varchar(255) NOT NULL, Version varchar(255), PRIMARY KEY (ID));")
    for k,v in cves.items():
        if len(v) == 0:
            sql = "INSERT INTO " + tableName + " (ID) VALUES (%s)"
            val = k
            cursor.execute(sql, val)
        else:
            v.sort()
            versions = str(v[0]) + "-" + str(v[-1])
            print(versions)
            sql = "INSERT INTO " + tableName + " (ID, Version) VALUES (%s, %s)"
            val = (k, versions)
            cursor.execute(sql, val)
            conn.commit()
        sql = "ALTER TABLE `{table}` ADD `lastUpdated` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP NOT NULL DEFAULT %s ;".format(table=tableName)
        val = [current_time]
        cursor.execute(sql, val)
        conn.commit()
    conn.close()

def containsDigit(version):
    return any(char.isdigit() for char in version)

# Defining main function
def main():
    print("here")
    #create_database()
    end = datetime.datetime.now()
    last_date = datetime.datetime(2023, 1, 1)
    keyword_string = 'java-merge-sort'
    create_database(end, last_date, keyword_string)




# Using the special variable 
# __name__
if __name__=="__main__":
    main()
