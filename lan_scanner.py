import os
import re
import sys
import time
import threading
import sqlite3
from flask import Flask, render_template, request
from datetime import datetime

# Scanner
AUTOKICK = False
DEFAULT_DEVICE_STATE = 0
POLL = 5

# Database 
SQLITE_DB_PATH = "scanner.db"
SQLITE_DB_TABLE = "mac_list"
SQLITE_DB_MODEL = ["id", "mac", "authorized", "name", "ip", "last_seen"]


    #######
    # GUI #
    #######

app = Flask(__name__)

@app.route("/")
def home(data=[]):
    return render_template('scanner.html', data=load_db())

@app.route("/update_state", methods=['POST'])
def update_id():
	id = int(request.form['id'])
	state = request.form['value']
	update_authorized(id, state)
	return "Done" 

@app.route("/update_name", methods=['POST'])
def update_name():
	id = int(request.form['id'])
	name = request.form['name']
	update_name(id, name)
	return "Done" 


    ###########
    # SCANNER #
    ###########

def launch_scanner(BSSID,interface):
	t = threading.Thread(target=scanner, args=(BSSID,interface,))
	t.daemon = True
	t.start()

def scanner(BSSID, interface):
	time.sleep(POLL)
	while True:
		li = os.popen("sudo arp-scan --interface={iface} --localnet".format(iface=interface)).read().split("\n")[2:-4]
		l = [(e.split("\t")[0], e.split("\t")[1]) for e in li]
		data = load_db()
		for detected_ip,detected_mac in l: 
			done = False
			# mac in db
			for line in data:
				if detected_mac == line['mac']:
					if detected_ip == line['ip']:
						update_last_seen_ip(line['id'], detected_ip)
					if line['authorized'] == 0 and AUTOKICK:
						kick(detected_mac)
						done = True
						break
					elif line['authorized'] == 0:
						warning_known(detected_mac, detected_ip)
						done = True
						break
					elif line['authorized'] == 1:
						done = True
						break
			# mac not in db
			if not done:
				insert_mac_in_db(detected_mac, detected_ip)
				warning_new(detected_mac, detected_ip)
				if AUTOKICK:
					kick(detected_mac)
		time.sleep(POLL)

		
    ############
    # DATABASE #
    ############

# Open or create the sqlite db file
# checks whether the default table exists
# and creates it if not
def check_db():
	with sqlite3.connect(SQLITE_DB_PATH) as conn:
		c = conn.cursor()
		c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'".format(table=SQLITE_DB_TABLE))
		exists = len(c.fetchall()) > 0
		if not exists:
			c.execute('''
				CREATE TABLE `{table}` (
					`id`			INTEGER PRIMARY KEY AUTOINCREMENT,
					`mac`			TEXT,
					`authorized`	TEXT,
					`name`			TEXT,
					`ip`			TEXT,
					`last_seen`		INTEGER
				)'''.format(table=SQLITE_DB_TABLE))
			conn.commit()

# Loads the whole content of the SQLITE_DB_TABLE table
# and returns a formatted list
def load_db():
	formated_data = []
	with sqlite3.connect(SQLITE_DB_PATH) as conn:
		c = conn.cursor()
		c.execute('SELECT * FROM {table}'.format(table=SQLITE_DB_TABLE))
		data = c.fetchall()
		for line in data:
			tmp_dic = {}.fromkeys(SQLITE_DB_MODEL)
			for n in range(len(line)):
				tmp_dic[SQLITE_DB_MODEL[n]] = line[n]
			tmp_dic['id'] = int(float(tmp_dic['id']))
			tmp_dic['authorized'] = int(float(tmp_dic['authorized']))
			tmp_dic['last_seen'] = datetime.fromtimestamp(tmp_dic['last_seen'])
			formated_data.append(tmp_dic)
	return formated_data

# Updates the authorized attribute in the db
# triggered by the on/off button of the GUI
def update_authorized(id, state):
	with sqlite3.connect(SQLITE_DB_PATH) as conn:
		c = conn.cursor()
		authorized = 1
		if state == 'false':
			authorized = 0
		c.execute('''
			UPDATE {table} SET authorized = ? WHERE id = ?
			'''.format(table=SQLITE_DB_TABLE), (authorized, id,))
		conn.commit()
	
# Updates the name of the mac address in the sqlite db
def update_name(id, name):
	with sqlite3.connect(SQLITE_DB_PATH) as conn:
		c = conn.cursor()
		c.execute('''
			UPDATE {table} SET name = ? WHERE id = ?
			'''.format(table=SQLITE_DB_TABLE), (name, id,))
		conn.commit()

def insert_mac_in_db(mac, ip):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('''
		INSERT INTO {table} (mac, ip, authorized, last_seen)
		VALUES (?, ?, ?, ?)
		'''.format(table=SQLITE_DB_TABLE), (mac, ip, DEFAULT_DEVICE_STATE, int(time.time())))
	conn.commit()
	conn.close()

def update_last_seen_ip(id, ip):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('''
		UPDATE {table} SET ip = ?, last_seen = ? WHERE id = ?
		'''.format(table=SQLITE_DB_TABLE), (ip, int(time.time()), id,))
	conn.commit()
	conn.close()	


    ###################
    # DEVICE HANDLING #
    ###################

def kick(mac):
	print("Kicking device", mac)
	cmd = os.popen("").read()

def warning_new(detected_mac, detected_ip):
	print("Warning new", detected_mac, detected_ip)

def warning_known(detected_mac, detected_ip):
	print("Warning known", detected_mac, detected_ip)
	

    ########
    # MAIN #
    ########

def usage():
	print("Usage : lan_scanner.py <BSSID> <scanning_iface>")
	exit(1)

if __name__ == "__main__":
	if len(sys.argv) != 3:
		usage()
	else:
		if re.match(r"^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$", sys.argv[1]) is None:
			usage()
		else:
			interface = sys.argv[2]
			BSSID = sys.argv[1]
			check_db()
			launch_scanner(BSSID, interface)
			app.run(debug=True)
