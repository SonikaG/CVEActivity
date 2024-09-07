from script import *
from packaging.version import Version


def test_mysql1():
    cves = {"key1": [Version("1.0.0"), Version("0.0.5"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = getRows('testDB')
    answer = result[0]
    assert(answer[0] == "key1")
    assert(answer[1] == "0.0.5-1.0.3")
    time = getRows('Meta')[0][1]
    assert(str(time) == current_time)
    print("TEST ONE PASSED")
    drop_table('testDB')
    drop_table('Meta')

def test_mysql2():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = getRows('testDB')
    answer = result[0]
    assert(answer[0] == "key1")
    assert(answer[1] == "1.0.0-1.0.3")
    time = getRows('Meta')[0][1]
    assert(str(time) == current_time)
    print("TEST TWO PASSED")
    drop_table('testDB')
    drop_table('Meta')


def test_mysql3():
    cves = {"key1": [] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = getRows('testDB')
    answer = result[0]
    assert(answer[0] == "key1")
    assert(answer[1] == None)
    time = getRows('Meta')[0][1]
    assert(str(time) == current_time)
    print("TEST THREE PASSED")
    drop_table('testDB')
    drop_table('Meta')


def test_mysql4():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = get_latest_timestamp_mysql('testDB')
    print(result)
    assert(str(result) == current_time)
    print("TEST FOUR PASSED")
    drop_table('testDB')

#this test cases were created from looking at CVE detail here: https://nvd.nist.gov/vuln/detail/CVE-2022-24913#range-12568480
def test_query_cpes_and_cves1():
    end = datetime.datetime(2023, 12, 20)
    last_date = datetime.datetime(2023, 1, 1)
    keyword_string = 'java-merge-sort'
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    assert(len(cpes) == 19)
    cves = queryCVES(cpes)
    print(cves.items())
    assert(len(cves.keys()) == 1)
    assert(list(cves.keys())[0] == "CVE-2022-24913")
    print("TEST FIVE PASSED")


def test_query_cpes_and_cves2():
    end = datetime.datetime(2024, 8, 20)
    last_date = datetime.datetime(2024, 8, 10)
    keyword_string = 'dog'
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    assert(len(cpes) == 0)
    cves = queryCVES(cpes)
    assert(len(cves) == 0)
    print("TEST SIX PASSED")


def test_mysql5():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = get_row_for_id('testDB', 'key1')
    print(result)
    drop_table('testDB')



def drop_table(tableName):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor. execute("DROP TABLE " + tableName + ";")
    conn.commit()
    conn.close()

def getRows(tableName):
    conn = mysql.connector.connect(user=MYSQL_SERVER, password=MYSQL_PASS, host=MYSQL_HOST, 
    port=MYSQL_PORT,database=MYSQL_DATABASE)
    cursor = conn.cursor()
    cursor. execute("SELECT * FROM " + tableName + ";")
    result = cursor.fetchall()
    conn.close()  
    return result

test_mysql1()
test_mysql2()
test_mysql3()
test_mysql4()
test_query_cpes_and_cves1()
test_query_cpes_and_cves2()
test_mysql5()