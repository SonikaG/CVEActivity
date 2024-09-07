from script import *
from packaging.version import Version


def test_mysql_create_database_multiversion():
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

def test_mysql_create_database_two_version():
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

def test_mysql_create_database_one_version():
    cves = {"key1": [Version("1.0.0")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = getRows('testDB')
    answer = result[0]
    assert(answer[0] == "key1")
    assert(answer[1] == "1.0.0-1.0.0")
    time = getRows('Meta')[0][1]
    assert(str(time) == current_time)
    print("TEST THREE PASSED")
    drop_table('testDB')
    drop_table('Meta')


def test_mysql_create_database_empty_version():
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
    print("TEST FOUR PASSED")
    drop_table('testDB')
    drop_table('Meta')


def test_mysql4_get_latest_timestamp():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = get_latest_timestamp_mysql('testDB')
    #print(result)
    assert(str(result) == current_time)
    print("TEST FIVE PASSED")
    drop_table('testDB')

#this test cases were created from looking at CVE detail here: https://nvd.nist.gov/vuln/detail/CVE-2022-24913#range-12568480
def test_query_cpes_and_cves_valid_string():
    end = datetime.datetime(2023, 12, 20)
    last_date = datetime.datetime(2023, 1, 1)
    keyword_string = 'java-merge-sort'
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    assert(len(cpes) == 19)
    cves = queryCVES(cpes)
    print(cves.items())
    assert(len(cves.keys()) == 1)
    assert(list(cves.keys())[0] == "CVE-2022-24913")
    print("TEST SIX PASSED")


def test_query_cpes_and_cves_no_result():
    end = datetime.datetime(2024, 8, 20)
    last_date = datetime.datetime(2024, 8, 10)
    keyword_string = 'dog'
    cpes = queryCPES(end, last_date, keyword_string, datetime.timedelta(days=30))
    assert(len(cpes) == 0)
    cves = queryCVES(cpes)
    assert(len(cves) == 0)
    print("TEST SEVEN PASSED")

def test_mysql_get_version_with_id():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    result = get_version_for_id('testDB', 'key1')
    assert(result == "1.0.0-1.0.3")
    print("TEST EIGHT PASSED")
    drop_table('testDB')
    drop_table('Meta')

def test_mysql_update_values_correct_version1():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    cves_new = {"key2": [Version("1.0.0"), Version("1.0.3")], "key1": [Version("1.3.0")]}
    current_time_2 = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    update_values_mysql('testDB', cves_new, current_time_2)
    result = get_version_for_id('testDB', 'key1')
    assert(result == "1.0.0-1.3.0")
    result = get_version_for_id('testDB', 'key2')
    assert(result == "1.0.0-1.0.3")
    result = get_latest_timestamp_mysql('testDB')
    assert(str(result) == current_time_2)
    print("TEST NINE PASSED")
    drop_table('testDB')
    drop_table('Meta')

def test_mysql_update_values_correct_version2():
    cves = {"key1": [Version("1.0.0"), Version("1.0.3")] }
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    create_database_mysql('testDB', current_time)
    insert_values_mysql('testDB', cves)
    cves_new = {"key2": [Version("1.0.0"), Version("1.0.3")], "key1": [Version("0.3.0")]}
    current_time_2 = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    update_values_mysql('testDB', cves_new, current_time_2)
    result = get_version_for_id('testDB', 'key1')
    assert(result == "0.3.0-1.0.3")
    result = get_version_for_id('testDB', 'key2')
    assert(result == "1.0.0-1.0.3")
    result = get_latest_timestamp_mysql('testDB')
    assert(str(result) == current_time_2)
    print("TEST TEN PASSED")
    drop_table('testDB')
    drop_table('Meta')

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

#run tests here
test_mysql_create_database_multiversion()
test_mysql_create_database_two_version()
test_mysql_create_database_one_version()
test_mysql_create_database_empty_version()
test_mysql4_get_latest_timestamp()
test_query_cpes_and_cves_valid_string()
test_query_cpes_and_cves_no_result()
test_mysql_get_version_with_id()
test_mysql_update_values_correct_version1()
test_mysql_update_values_correct_version2()