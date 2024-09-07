import mysql.connector
import nvdlib
import datetime
from packaging.version import Version
import sys
import argparse
from config import *

'''
function: a wrapper function for our calls to NIST API to get CPES, I use nvdlib see resources.txt
param1: the end time, where we start time from 
param2: last_datte where we want to stop (beginning of 2023)
param3: keyword string we are searching for in cpes
param4: delta is the time period we search for per api call, in this case I use 30 days
'''
def queryCPES(end, last_date, keyword_string, delta):
    start = end - delta
    cpes = []
    while(start > last_date):
        print("first loop")
        cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=start, lastModEndDate=end))
        start -= delta
        end -= delta
    cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=last_date, lastModEndDate=end))
    cpes = set(cpes)
    print(len(cpes))
    return cpes

'''
function: a wrapper funcion for our calls to NIST API to get CVES, I use nvdlib see resources.txt
param1: cpes that we should search for cves from 
'''
def queryCVES(cpes):
    cves = {}
    for cpe in cpes: 
        print("second loop")
        version = cpe.cpeName.split(":")[5]
        try:
            version = Version(version)
        except:
            version = None
        results = set(nvdlib.searchCVE(cpeName = cpe.cpeName))
        for cve in results: 
            if cve.id not in cves: 
                versions = []
                if version: 
                    versions.append(version)
                cves[cve.id] = versions
            else:
                #update version numbers
                if version:
                    cves[cve.id].append(version)
    #print(list(cves.items()))
    return cves

'''
function: a wrapper function to orchestrate all parts of initializing our database
param1: keyword string we are searching for in cves
param2: name of our cve table 
'''
def create_database(keyword_string, tableName):
    #end = datetime.datetime.now()
    end = datetime.datetime(2023, 2, 28)
    current_time = end.strftime('%Y-%m-%d %H:%M:%S')
    last_date = datetime.datetime(2023, 1, 1)
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    cves = queryCVES(cpes)
    try:
        create_database_mysql(tableName, current_time)
        insert_values_mysql(tableName, cves)
    #we want to clean up the DB in case of error 
    except Exception:
        drop_table(tableName)
        drop_table('Meta')
        print(Exception)
        raise()

'''
function: a wrapper function that orchestrates all parts of updating our database
param1: keyword string we are searching for in cves
param2: name of our cve table 
'''
def update_database(keyword_string, tableName):
    #we need the last time we ran a cve query so we don't query this time for data we already have
    last_date = get_latest_timestamp_mysql(tableName)
    end = datetime.datetime.now()
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    cves =  queryCVES(cpes)  
    #now we have a new time for when we last queried for cves 
    current_time = end.strftime('%Y-%m-%d %H:%M:%S')
    try:
        update_values_mysql(tableName, cves, current_time)
    #we want to clean up the DB in case of error 
    except Exception:
        drop_table(tableName)
        drop_table('Meta')
        print(Exception)
        raise()
    
'''
function to update our database with new cves, old cves with new version information 
param1: name of our cve table
param2: map of cve_id to versions
param3: time of last cve query so that we can update that value in our Meta table 
'''
def update_values_mysql(tableName, cves, current_time):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cves_to_insert = {}
    for k,v in cves.items():
        #check if we have the row already
        version = get_version_for_id(tableName, k)
        #if this row exists in database
        if version:
            #if we have new version number(s)
            if len(v) > 0:
                v.sort()
                old_version = version.split("-")
                new_version = ""
                if v[0] < Version(old_version[0]):
                    new_version += str(v[0])
                else:
                    new_version += old_version[0]
                new_version += "-"
                if v[-1] > Version(old_version[1]):
                    new_version += str(v[-1])
                else:
                    new_version += old_version[1]
                sql = "UPDATE " + tableName + " SET Version = %s WHERE ID = %s"
                val = [new_version, k]
                cursor.execute(sql, val)  
        #we need to insert new values
        else:
            cves_to_insert[k] = v
    insert_values_mysql(tableName, cves_to_insert)
    sql = ("UPDATE INTO Meta (Tablename, lastUpdated) VALUES (%s, %s)")
    val = [tableName, current_time]
    conn.commit()
    conn.close()

'''
fucntion to get version information for a cve_id if it exists
param1: the name of our cve table
param2: id we are looking for 
'''
def get_version_for_id(tableName, id):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    sql = "SELECT Version FROM " + tableName + " WHERE ID = %s"
    val = [id]
    cursor.execute(sql,val)
    result = cursor.fetchall()
    if len(result) > 0:
        return result[0][0]  
    else:
        return None  

'''
function to insert cve and versions into our database
param1: the name of our cve table 
param2: a map of cve_id to version 
'''
def insert_values_mysql(tableName, cves):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    for k,v in cves.items():
        #Do we have version numbers then?
        if len(v) == 0:
            sql = "INSERT INTO " + tableName + " (ID) VALUES (%s);"
            val = [k]
            cursor.execute(sql, val)
            conn.commit()
        #if we do have version numbers include those in INSERT statement 
        else:
            v.sort()
            versions = str(v[0]) + "-" + str(v[-1])
            sql = "INSERT INTO " + tableName + " (ID, Version) VALUES (%s, %s)"
            val = (k, versions)
            cursor.execute(sql, val)
    #all or nothing commit -- not the most efficient but it's there to prevent errors for now
    #in the next iteration, ideally it would be batch committed so progress isn't lost 
    conn.commit()
    conn.close()
'''
fucntion to create our database and a meta database
param1: name of the database that stores our cve data
param2: we want to store the time we queried the cves so that on update we startt from that time
'''
def create_database_mysql(tableName, current_time):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS " +  tableName + " (ID varchar(255) NOT NULL, Version varchar(255), PRIMARY KEY (ID));")
    #NOTE: This is where we also create a Meta table. This is to keep track of the last time we updated the cve table (or any table)
    cursor.execute("CREATE TABLE IF NOT EXISTS Meta (Tablename varchar(255), lastUpdated TIMESTAMP);")
    sql = ("INSERT INTO Meta (Tablename, lastUpdated) VALUES (%s, %s)")
    val = [tableName, current_time]
    cursor.execute(sql, val)
    conn.commit()
    conn.close()

'''
Funciton to get the latest update timestamp from the database for a given table
param1 tableName: the table we want the lastUpdate time for
'''
def get_latest_timestamp_mysql(tableName):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT lastUpdated FROM Meta WHERE Tablename = '" + tableName + "'" )
    result = cursor.fetchall()
    return result[0][0]

def drop_table(tableName):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor. execute("DROP TABLE IF EXISTS " + tableName + ";")
    conn.commit()
    conn.close()

def main():
    print("here")
    keyword_string = 'java-merge-sort'
    tableName = 'cve'
    #from here: https://stackoverflow.com/questions/8259001/python-argparse-command-line-flags-without-arguments
    parser = argparse.ArgumentParser(description='create or update nist database with java packages')
    parser.add_argument('action', help='please provide either create or update')
    args = parser.parse_args()
    action = args.action
    print(action)
    if not (action == "create" or action == "update"):
        print("action arguementt can only be \"create\" or \"update\"")
        sys.exit()
    if (action == "create"):
        create_database(keyword_string, tableName)
    elif (action == "update"):
        update_database(keyword_string, tableName)

# Using the special variable 
# __name__
if __name__=="__main__":
    main()
