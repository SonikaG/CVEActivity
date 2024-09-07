import mysql.connector
import nvdlib
import datetime
from packaging.version import Version
import sys

from config import *

def queryCPES(end, last_date, keyword_string, delta):
    start = end - delta
    cpes = []
    while(start > last_date):
        print("in loop")
        cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=start, lastModEndDate=end))
        start -= delta
        end -= delta
    cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=last_date, lastModEndDate=end))
    cpes = set(cpes)
    return cpes

def queryCVES(cpes):
    cves = {}
    for cpe in cpes: 
        #print(cpe.cpeName)
        print("in second loop")
        version = cpe.cpeName.split(":")[5]
        if (containsDigit(version)):
            version = Version(version)
        else:
            version = None
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
    return cves


def create_database(end, last_date, keyword_string):
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    return queryCVES(cpes)

def insert_values_mysql(tableName, cves):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    for k,v in cves.items():
        if len(v) == 0:
            sql = "INSERT INTO " + tableName + " (ID) VALUES (%s);"
            val = [k]
            cursor.execute(sql, val)
            conn.commit()
        else:
            v.sort()
            versions = str(v[0]) + "-" + str(v[-1])
            #print(versions)
            sql = "INSERT INTO " + tableName + " (ID, Version) VALUES (%s, %s)"
            val = (k, versions)
            cursor.execute(sql, val)
            conn.commit()
    conn.close()

def create_database_mysql(tableName, current_time):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS " +  tableName + " (ID varchar(255) NOT NULL, Version varchar(255), PRIMARY KEY (ID));")
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
    end = datetime.datetime.now()
    end = datetime.datetime(2023, 2, 28)
    current_time = end.strftime('%Y-%m-%d %H:%M:%S')
    last_date = datetime.datetime(2023, 1, 1)
    keyword_string = 'java-merge-sort'
    cves = create_database(end, last_date, keyword_string)
    create_database_mysql('cve', current_time)
    insert_values_mysql('cve', cves)





# Using the special variable 
# __name__
if __name__=="__main__":
    main()
