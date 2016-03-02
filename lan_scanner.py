import os
import re
import sys
import time
import threading
import sqlite3
from flask import Flask, render_template, request

AUTOKICK = False
DEFAULT_DEVICE_STATE = 0
POLL = 5
SQLITE_DB_PATH = "scanner.db"

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
			for id,mac,authorized,name,last_seen in data:
				if detected_mac == mac:
					if last_seen == detected_ip:
						update_last_seen_ip(id, detected_ip)
						print("Updating ", detected_ip, "on id", id)
					if authorized == 0 and AUTOKICK:
						kick(detected_mac)
						done = True
						break
					elif authorized == 0:
						warning_known(detected_mac, detected_ip)
						done = True
						break
					elif authorized == 1:
						done = True
						break
			# mac not in db
			if not done:
				insert_mac_in_db(detected_mac, detected_ip)
				warning_new(detected_mac, detected_ip)
				if AUTOKICK:
					kick(detected_mac)
		time.sleep(POLL)
		
def load_db():
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('SELECT * FROM mac_list')
	data = c.fetchall()
	conn.close()
	return data

def update_authorized(id, state):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	authorized = 1
	if state == 'false':
		authorized = 0
	c.execute('UPDATE mac_list SET authorized = "' + str(authorized) + '" WHERE id = ' + str(id))
	conn.commit()
	conn.close()

def update_name(id, name):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('UPDATE mac_list SET name = "' + name + '" WHERE id = ' + str(id))
	conn.commit()
	conn.close()	

def insert_mac_in_db(mac, ip):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('INSERT INTO mac_list (mac, ip, authorized)	VALUES ("'+mac+'", "'+ip+'", "'+str(DEFAULT_DEVICE_STATE)+'");')
	conn.commit()
	conn.close()

def update_last_seen_ip(id, ip):
	conn = sqlite3.connect(SQLITE_DB_PATH)
	c = conn.cursor()
	c.execute('UPDATE mac_list SET ip = "' + ip + '" WHERE id = ' + str(id))
	conn.commit()
	conn.close()	

def kick(mac):
	print("Kicking device", mac)
	cmd = os.popen("").read()

def warning_new(detected_mac, detected_ip):
	print("Warning new", detected_mac, detected_ip)

def warning_known(detected_mac, detected_ip):
	print("Warning known", detected_mac, detected_ip)

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
			launch_scanner(BSSID, interface)
			app.run(debug=True)
