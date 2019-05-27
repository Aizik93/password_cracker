# General

## Files
### Master:
•	master.py – master script<br>
•	master.db – sql db with a table for opened sessions<br>
•	master.json – json file includes master’s status, port and number of minions<br>

### Minion:<br>
•	minion.py – minion script <br>
•	minion.db – sql db with a table for minion calculated hashes: [hash, password] <br>
•	minion.json – json file includes minion status and port <br>

### Session:
Before uploading a hash file, you must first open a new session. <br>
Then, you upload your file to the session you opened.<br>
Session.json – for each opened session there is a json file includes session status

## Input files:
Examples of possible input hash files and the correspond password files.

## Environment:
Master and Minions servers should run on a python3 (run on 3.7 version) and use SQLite to manage the db. <br>
To install required libraries just run the following command: <br>
*pip install -r requirements.txt*

## Running Instructions:
1.	First you should run Master server. <br>
Run the python script:<br>
*python master.py*
2.	Open a new session with Master server by send the following GET request:<br>
*http://localhost:<master_port>/new_session*<br>
The session id will returned in a json format.
3.	Upload your hashes text file to the following POST request:<br>
*http://localhost:<master_port>/sessions/<session_id>/upload*
4.	Use the following command to get your result: <br>
*http://localhost:<master_port>/sessions/<session_id>/status*<br>
The output is a json with the following possible status:
    * ‘busy’ status means that it still calculating
    * ‘finished’ status will be returned with a list of the passwords (in the same order of hashes)


Adding Minions: Note that you can use as much minions as you want by changing minions number in master's json file. <br> 


## Flow Explanation:
### Master
1.	Master creates a session, and a json file to the session.
2.	Master gets user’s file and creates a hash list.
3.	Master creates minions as much as specified in the json file.
4.	Master send a message to each available minion to start calculation on a specific range.
5.	Master creates a process that checks every 3 seconds if a hash is found in each of the minions. If one of the minions found it, the process moves to the next hash.
6.	Master creates a process the checks every 2 seconds if a all of the minions are working. If one of them doesn’t response for a timeout, the Master splits it’s ranges to other minions.
7.	Master saves the passwords in the session file when it finish deciphering.

### Minion
1.	Gets a range to calculate from the Master, and updates it’s database every 100 passwords
2.	Gets requests from Master to check for a hash in it’s db.
3.	Gets a request from the Master to stop calculating.


## Notes:
* If one of the minions is terminated during the calculation, the master will split this minion’s job to other minions.
* The Master assumes that all of the hashes belongs to phone numbers in the following format: 05XXXXXXXX
* For each file upload, deciphering process start from the beginning and not using past password calculations.
* Each calculation in the minion is printed to standard output as a log.
