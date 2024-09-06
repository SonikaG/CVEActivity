import mysql.connector
import nvdlib
import datetime
from packaging.version import Version
import sys

def create_database():
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=30)
    last_date = datetime.datetime(2023, 1, 1)
    cpes = []
    while(start > last_date):
        print("in loop")
        cpes += (nvdlib.searchCPE(keywordSearch = 'java-merge-sort', key = 'da031268-411b-4cfb-9e67-0f5b5d949299', lastModStartDate=start, lastModEndDate=end))
        start -= datetime.timedelta(days=30)
        end -= datetime.timedelta(days=30) 
    cpes += (nvdlib.searchCPE(keywordSearch = 'java-merge-sort', key = 'da031268-411b-4cfb-9e67-0f5b5d949299', lastModStartDate=last_date, lastModEndDate=end))
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

    #for k,v in cves.items():


def create_database_mysql(cves):
    conn = mysql.connector.connect(user='XXXX', password='XXXX', host='XXXX', 
    port='XXXX',database='XXXX')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE Cves (ID varchar(255) NOT NULL, Version varchar(255), PRIMARY KEY (ID));")
    for k,v in cves.items():
        if len(v) == 0:
            sql = "INSERT INTO Cves (ID) VALUES (%s)"
            val = k
            cursor.execute(sql, val)
        else:
            v.sort()
            versions = str(v[0]) + ", " + str(v[:-1])
            sql = "INSERT INTO Cves (ID, Version) VALUES (%s, %s)"
            val = (k, versions)
            cursor.execute(sql, val)
    conn.close()

def containsDigit(version):
    return any(char.isdigit() for char in version)

# Defining main function
def main():
    print("here")
    #create_database()
    create_database_mysql()




# Using the special variable 
# __name__
if __name__=="__main__":
    main()
