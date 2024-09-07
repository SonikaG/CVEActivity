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
        cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=start, lastModEndDate=end))
        start -= delta
        end -= delta
    cpes += (nvdlib.searchCPE(keywordSearch = keyword_string, key = NIST_API_KEY, lastModStartDate=last_date, lastModEndDate=end))
    cpes = set(cpes)
    return cpes

def queryCVES(cpes):
    cves = {}
    for cpe in cpes: 
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

def create_database(keyword_string, tableName):
    end = datetime.datetime.now()
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


def update_database(keyword_string, tableName):
    last_date = get_latest_timestamp_mysql(tableName)
    end = datetime.datetime.now()
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    cves =  queryCVES(cpes)  
    current_time = end.strftime('%Y-%m-%d %H:%M:%S')
    try:
        update_values_mysql(tableName, cves, current_time)
    #we want to clean up the DB in case of error 
    except Exception:
        drop_table(tableName)
        drop_table('Meta')
        print(Exception)
        raise()
    

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
            #if we can update version number
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
    #all or nothing commit -- not the most efficient but it's there to prevent errors for now
    #in the next iteration, ideally it would be batch committed so progress isn't lost 
    conn.commit()
    conn.close()

def create_database_mysql(tableName, current_time):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS " +  tableName + " (ID varchar(255) NOT NULL, Version varchar(255), PRIMARY KEY (ID));")
    cursor.execute("CREATE TABLE IF NOT EXISTS Meta (Tablename varchar(255), lastUpdated TIMESTAMP);")
    sql = ("INSERT INTO Meta (Tablename, lastUpdated) VALUES (%s, %s)")
    val = [tableName, current_time]
    cursor.execute(sql, val)
    conn.commit()
    conn.close()

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
    cursor. execute("DROP TABLE " + tableName + ";")
    conn.commit()
    conn.close()


def containsDigit(version):
    return any(char.isdigit() for char in version)


def main():
    print("here")
    '''end = datetime.datetime.now()
    end = datetime.datetime(2023, 2, 28)
    current_time = end.strftime('%Y-%m-%d %H:%M:%S')
    last_date = datetime.datetime(2023, 1, 1)'''
    keyword_string = 'java-merge-sort'
    tableName = 'cve'
    create_database(keyword_string, tableName)
    '''create_database_mysql('cve', current_time)
    insert_values_mysql('cve', cves)'''

# Using the special variable 
# __name__
if __name__=="__main__":
    main()
