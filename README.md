# CVEActivity

This product uses data from the NVD API but is not endorsed or certified by the NVD

## Prerequisites: 
1) Make sure you have [mysql installed](https://www.mysql.com/downloads/) and create a database. Instructions for [MacOs](https://www.geeksforgeeks.org/how-to-install-mysql-on-macos/)
2) Make sure to run `pip install requirements.txt`
3) Make sure to update the config.py file with all your mqsql database/server details. You need a NIST API Key [here](https://nvd.nist.gov/developers/request-an-api-key)

## How To Use
Call the script as such: `/path/to/python3/ script.py create` to create the database OR `/path/to/python3/ script.py update` to update it

## Rationale 
### Datastore
I chose to use a mysql database to store cve value and versions. 
### Fetching NIST CVE's 
1) I chose to directly use the NIST Feed API so that data is as up-to-date as possible. This decision was also made because there is an existing [python library](https://pypi.org/project/nvdlib//) that rate limits and abides by the NIST API developer ask that requests sleep 6 seconds, requiring me to do less. One of the downsides of this approach is that the library does all the error handling. This isn't an issue for all status codes, but for example, sometimes the library does not retry when reads take a long time and the API returns with an error.
2) My algorithm to fetch cve's is as follows:
   1) fetch cpe with 'java' somewhere in the json see:[link](https://nvdlib.com/en/latest/v2/CPEv2.html#nvdlib.cpe.searchCPE) and with lastModifiedDate within our time range 2023-now
   2) loop through those cpe's and get [version number](https://en.wikipedia.org/wiki/Common_Platform_Enumeration) and then the associated cves
   3) Use the above information to make a map or cve_id to all affected versions
### Writing into Database
I use the above map to populate my database. I take the list of affectted versions and sort it and use that to get a range. 
### Updating the Database with new daa
1) I use the same algorithm above but instead of staring from now to 2023, I use a lastupdate number I saved to be the start of timeframe and the end being now. The lastupdate is first set when we call the NIST API to create the databse and then also set everytime we update. 
2) Going through my map of cve.id to versions I:
   1) Check if this cve exists in the database:
      a) if it doesn't: I insert a new row
      b) if it does: I check if we have updated version information and only update the table if we do

NOTE: I explicitly set my cve.id to be the primary key of my table to benefit performance

## AI Tools: None Used

## Improvements (NOTE: you can find comments about this in the code as well):
There's stuff I would like to call out as additional adds or changes I would make in the future: 
1) Error handling. While creating and updating the database, the write to the database is all or nothing. If we succesfully get through the whole process than great, otherwise we start from the beginning. In the future, I would change this to batching. 
2) My test code was really written for myself. There could be a testing framework. I would also add mock API calls to really test out if my NIST API call logic works correctly.Currently, I corroborated results with the NIST database. 
3) Add a verbose version to the script for debugging
4) Currently, if you call update without calling create, it just errors out with a low-level sql exception. Ideally, we woudld tell the user of their error



   

