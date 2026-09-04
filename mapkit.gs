// Command mapkit v3.0
//print("Booting Mapkit V3.0...")
//wait(0.2)
//print("Gathering necessary File's and Lib's please wait!")
//wait(0.2)
//print("Starting Mapkit V3.0")
//wait(0.2)
//print("Loading complete!")
//wait(0.2)
//print("Starting...")
//wait(0.2)
if params.len != 1 or params[0] == "-h" or params[0] == "--help" then exit ("<b>Usage: "+program_path.split("/")[-1]+" [ip_address]</b>")

metax = include_lib("/lib/metaxploit.so")
if not metax then exit ("<b>Error: Unable to find 'metaxploit.so'. Put missing library in the '/lib' folder</b>")

cryptools = include_lib("/lib/crypto.so")

shell = get_shell
computer = shell.host_computer
password = "password"

if not is_valid_ip(params[0]) then exit ("<b>Error: Invalid IP address.</b>")
if not computer.is_network_active then exit ("<b>Error: No internet access.</b>")

ipAddress = params[0]
if ipAddress == "127.0.0.1" then ipAddress = computer.local_ip

isLanIp = is_lan_ip(ipAddress)
if isLanIp then
    router = get_router
else
    router = get_router(ipAddress)
end if
if router == null then exit ("<b>mapkit: ip address not found</b>")

if not isLanIp then
    ports = router.used_ports
else
    ports = router.device_ports(ipAddress)
end if
if ports == null then exit ("<b>mapkit: ip address not found</b>")
if typeof(ports) == "string" then exit(ports)

// --- Folder setup ---
targetsFolderName = "targets"
targetsFolderPath = "/"
targetsFolder = "/" + targetsFolderName
txtName = ipAddress + ".txt"
txtFullPath = targetsFolder + "/" + txtName

if computer.File(targetsFolder) == null then
    computer.create_folder(targetsFolderPath, targetsFolderName)
end if

// --- Global: Track discovered services on target ---
discoveredServices = []  // each entry: {"name": libName, "version": libVersion, "port": portNumber}

// ================================================================
//  SMART HARVEST (Uses exploits from /targets/<router_ip>/)
// ================================================================

// --- Helper: get router exploits for a specific version (only Computer/File) ---
get_router_exploits = function(routerIP, targetsFolder, targetVersion)
    exploits = []
    libFolderName = "kernel_router.so_v" + targetVersion
    libDir = computer.File(targetsFolder + "/" + libFolderName)
    if libDir == null then
        print("  No kernel_router.so_v" + targetVersion + " folder found.")
        return exploits
    end if
    
    if not libDir.is_folder then
        return exploits
    end if
    
    for f in libDir.get_files
        content = f.get_content
        if content == null then continue
        isComputer = false
        isFile = false
        port = ""
        zone = ""
        exploit = ""
        for line in content.split(char(10))
            if line.indexOf("Result: Computer") == 0 then isComputer = true
            if line.indexOf("Result: File") == 0 then isFile = true
            if line.indexOf("Port: ") == 0 then port = line[6:]
            if line.indexOf("Zone: ") == 0 then zone = line[6:]
            if line.indexOf("Exploit: ") == 0 then exploit = line[9:]
        end for
        if (isComputer or isFile) and zone != "" and exploit != "" then
            expType = "File"
            if isComputer then expType = "Computer" end if
            exploits.push({"zone": zone, "exploit": exploit, "port": port, "type": expType})
        end if
    end for
    return exploits
end function

// --- Helper: get service exploits for a specific version (only Computer/File) ---
get_service_exploits = function(targetsFolder, targetLibName, targetVersion)
    serviceExploits = []
    libFolderName = targetLibName + "_v" + targetVersion
    libDir = computer.File(targetsFolder + "/" + libFolderName)
    if libDir == null then
        altFolderName = targetLibName + "_" + targetVersion
        libDir = computer.File(targetsFolder + "/" + altFolderName)
    end if
    if libDir == null then
        print("  No " + libFolderName + " folder found.")
        return serviceExploits
    end if
    
    if not libDir.is_folder then
        return serviceExploits
    end if
    
    for f in libDir.get_files
        content = f.get_content
        if content == null then continue
        isComputer = false
        isFile = false
        port = ""
        zone = ""
        exploit = ""
        for line in content.split(char(10))
            if line.indexOf("Result: Computer") == 0 then isComputer = true
            if line.indexOf("Result: File") == 0 then isFile = true
            if line.indexOf("Port: ") == 0 then port = line[6:]
            if line.indexOf("Zone: ") == 0 then zone = line[6:]
            if line.indexOf("Exploit: ") == 0 then exploit = line[9:]
        end for
        if (isComputer or isFile) and zone != "" and exploit != "" and port != "" and port != "0" then
            expType = "File"
            if isComputer then expType = "Computer" end if
            serviceExploits.push({"zone": zone, "exploit": exploit, "port": port.to_int, "lib": targetLibName, "type": expType})
        end if
    end for
    return serviceExploits
end function

// --- Helper: try exploits until one gives a computer object ---
try_exploits_for_computer = function(routerLib, lanIP, exploits)
    for exp in exploits
        print("  Trying exploit: " + exp.zone + " / " + exp.exploit + " (hoping for Computer)")
        result = routerLib.overflow(exp.zone, exp.exploit, lanIP)
        if result != null and typeof(result) == "computer" then
            print("  Got Computer access on " + lanIP + " using " + exp.exploit)
            return result
        end if
    end for
    return null
end function

// --- Helper: try exploits until one gives a file object (maybe /home) ---
try_exploits_for_file = function(routerLib, lanIP, exploits)
    for exp in exploits
        print("  Trying exploit: " + exp.zone + " / " + exp.exploit + " (hoping for File)")
        result = routerLib.overflow(exp.zone, exp.exploit, lanIP)
        if result != null and typeof(result) == "file" then
            print("  Got File access on " + lanIP + " using " + exp.exploit)
            return result
        end if
    end for
    return null
end function

// --- Helper: try service exploits to get a computer or file object ---
try_service_exploits = function(lanIP, serviceExploits)
    for exp in serviceExploits
        print("    Trying service exploit: " + exp.lib + " port " + exp.port + " " + exp.zone + "/" + exp.exploit)
        net_session = metax.net_use(lanIP, exp.port)
        if net_session == null then
            print("    Could not connect to port " + exp.port + " on " + lanIP)
            continue
        end if
        metaLib = net_session.dump_lib
        result = metaLib.overflow(exp.zone, exp.exploit, password)
        if result != null then
            if typeof(result) == "computer" or typeof(result) == "file" then
                print("    Got " + typeof(result) + " access via " + exp.lib)
                return result
            end if
        end if
    end for
    return null
end function

// --- Helper: Get privilege level from a shell (maps to root/user/guest) ---
get_shell_user = function(shell)
    if shell == null then return "unknown"
    
    username = null
    
    // First try direct properties
    if shell.hasIndex("user") and typeof(shell.user) == "string" then
        username = shell.user
    else if shell.hasIndex("username") and typeof(shell.username) == "string" then
        username = shell.username
    else if shell.hasIndex("get_user") then
        u = shell.get_user()
        if u != null and typeof(u) == "string" then username = u
    end if
    
    if username != null then
        uname_lower = username.lower
        if uname_lower == "root" then return "root"
        if uname_lower == "guest" then return "guest"
        return "user"
    end if
    
    // Try whoami via shell.launch
    temp_file = "/tmp/whoami_temp.txt"
    shell.launch("/bin/whoami", "> " + temp_file)
    wait(1)
    host = get_shell.host_computer
    if host.File(temp_file) != null then
        content = host.File(temp_file).get_content
        if content != null then
            content = content.trim
            host.File(temp_file).delete
            if content != "" then
                uname_lower = content.lower
                if uname_lower == "root" then return "root"
                if uname_lower == "guest" then return "guest"
                return "user"
            end if
        end if
    end if
    
    // Try host_computer.user
    if shell.hasIndex("host_computer") then
        host = shell.host_computer
        if host != null and host.hasIndex("user") then
            u = host.user
            if u != null and typeof(u) == "string" then
                uname_lower = u.lower
                if uname_lower == "root" then return "root"
                if uname_lower == "guest" then return "guest"
                return "user"
            end if
        end if
    end if
    
    return "unknown"
end function

// --- Helper: Process passwd file (decrypt hashes) ---
process_passwd_file = function(fileObj)
    if fileObj == null then return
    content = null
    if fileObj.hasIndex("get_content") then
        content = fileObj.get_content
    else if fileObj.hasIndex("content") then
        content = fileObj.content
    end if
    if content == null then return
    
    print("  [Passwd] Decrypting entries:")
    lines = content.split("\n")
    for line in lines
        line = line.trim
        if line == "" then continue
        parts = line.split(":")
        if parts.len >= 2 then
            username = parts[0]
            hash = parts[1]
            decrypted = null
            if cryptools != null then
                decrypted = cryptools.decipher(hash)
            end if
            if decrypted != null then
                print("    " + username + ":" + hash + " -> " + decrypted)
            else
                print("    " + username + ":" + hash + " (decryption failed)")
            end if
        end if
    end for
end function

// ================================================================
// --- PORT SCAN ---
// ================================================================

output = ""
info = "PORT STATE SERVICE VERSION LAN"
openPorts = []

print("\nStarting mapkit v3.0 at " + current_date)
print("Interesting ports on " + ipAddress + "\n")

for port in ports
    service_info = router.port_info(port)
    lan_ips = port.get_lan_ip
    port_status = "open"
    if port.is_closed and not isLanIp then
        port_status = "closed"
    else
        openPorts.push(port)
    end if
    info = info + "\n" + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
end for

print(format_columns(info) + "\n")
output = output + format_columns(info) + char(10)

new_types = []
ssh_scanned = false
ftp_scanned = false
http_scanned = false
sql_scanned = false
smtp_scanned = false

// ================================================================
// --- ROUTER SCAN ---
// ================================================================

print("\n--- Scanning Router ---")

routerVersion = router.kernel_version
if not routerVersion then
    print("Warning: kernel_router.so not found")
else
    print("kernel_router.so : v" + routerVersion)
end if

firewall_rules = router.firewall_rules
if typeof(firewall_rules) != "string" and firewall_rules.len > 0 then
    print("\nFirewall rules:")
    fwInfo = "ACTION PORT SOURCE_IP DESTINATION_IP"
    for rule in firewall_rules
        fwInfo = fwInfo + "\n" + rule
    end for
    print(format_columns(fwInfo) + "\n")
    output = output + char(10) + "FIREWALL RULES:" + char(10) + format_columns(fwInfo) + char(10)
else
    print("No firewall rules found.")
end if

if routerVersion then
    libFolderName = "kernel_router.so_v" + routerVersion
    libFolder = targetsFolder + "/" + libFolderName
    if computer.File(libFolder) != null then
        print("\nSkipping kernel_router.so (already scanned)")
    else
        computer.create_folder(targetsFolder, libFolderName)
        routerSession = metax.net_use(ipAddress, 0)
        if routerSession then
            routerLib = routerSession.dump_lib
            print("\nScanning kernel_router.so v" + routerVersion + " with metaxploit...")
            output = output + char(10) + char(10) + "ROUTER: kernel_router.so v" + routerVersion
            scanResult = metax.scan(routerLib)
            for zone in scanResult
                memory_scan = metax.scan_address(routerLib, zone)
                print("\nFound router zone: " + zone)
                output = output + char(10) + char(10) + "Exploits for zone: " + zone
                xpList = memory_scan.split("Unsafe check")[1:]
                exploits = []
                shellExploits = []
                for xp in xpList
                    labelStart = xp.indexOf("<b>")
                    labelEnd = xp.indexOf("</b>")
                    exploit = xp[labelStart + 3: labelEnd]
                    print("\nTesting router exploit: " + exploit)
                    wait(0.5)
                    result = routerLib.overflow(zone, exploit, password)
                    if result == null then
                        status = "Undefined / Conditional"
                    else if typeof(result) == "shell" then
                        user = get_shell_user(result)
                        status = "Shell (" + user + ")"
                        shellExploits.push(exploit)
                    else if typeof(result) == "firewall" then
                        status = "Firewall"
                        print("Firewall rule obtained!")
                    else if typeof(result) == "file" then
                        status = "File"
                        if result.path.indexOf("passwd") != -1 or result.path.indexOf("shadow") != -1 then
                            process_passwd_file(result)
                        end if
                    else if typeof(result) == "folder" then
                        status = "Folder"
                    else if typeof(result) == "number" then
                        status = "Password: '" + password + "'"
                    else if typeof(result) == "computer" then
                        status = "Computer"
                    else
                        status = "New type: " + typeof(result)
                        if new_types.indexOf(typeof(result)) == null then
                            new_types.push(typeof(result))
                        end if
                    end if
                    exploits.push(exploit + " (" + status + ")")
                    originalName = zone + "_" + exploit
                    safeName = ""
                    allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                    for ch in originalName
                        if allowedChars.indexOf(ch) != null then
                            safeName = safeName + ch
                        else if ch == " " then
                            safeName = safeName + "_"
                        end if
                    end for
                    safeName = safeName + ".txt"
                    vulnContent = "Library: kernel_router.so v" + routerVersion + char(10)
                    vulnContent = vulnContent + "Port: 0" + char(10)
                    vulnContent = vulnContent + "Zone: " + zone + char(10)
                    vulnContent = vulnContent + "Exploit: " + exploit + char(10)
                    vulnContent = vulnContent + "Result: " + status + char(10)
                    computer.touch(libFolder, safeName)
                    libFolderObj = computer.File(libFolder)
                    vulnFile = null
                    for f in libFolderObj.get_files
                        if f.name == safeName then
                            vulnFile = f
                            break
                        end if
                    end for
                    if vulnFile != null then
                        vulnFile.set_content(vulnContent)
                    else
                        print("<b>Warning: Could not write router vuln file: " + safeName + "</b>")
                    end if
                    wait(0.5)
                end for
                if shellExploits.len > 0 then
                    print("\nShell exploits for zone " + zone + ": " + shellExploits.join(", "))
                else
                    print("\nNo shell exploits for zone " + zone)
                end if
                output = output + char(10) + exploits.join(char(10))
            end for
        else
            print("Could not connect to router via metaxploit.")
        end if
    end if
end if

// ================================================================
// --- TARGET PORT SCAN (Populates discoveredServices) ---
// ================================================================

if ports.len == 0 then
    print("\nNo open ports found on target.")
else
    for port in ports
        net_session = metax.net_use(ipAddress, port.port_number)
        if not net_session then
            print("<b>mapkit: failed to connect to port " + port.port_number + ", skipping</b>")
            continue
        end if

        metaLib = net_session.dump_lib
        libName = metaLib.lib_name
        libVersion = metaLib.version

        if libName.indexOf("ssh") != null and ssh_scanned then
            continue
        else if libName.indexOf("ftp") != null and ftp_scanned then
            continue
        else if libName.indexOf("http") != null and http_scanned then
            continue
        else if libName.indexOf("sql") != null and sql_scanned then
            continue
        else if libName.indexOf("smtp") != null and smtp_scanned then
            continue
        end if

        discoveredServices.push({"name": libName, "version": libVersion, "port": port.port_number})

        libFolderName = (libName + "_v" + libVersion).replace(" ", "_")
        libFolder = targetsFolder + "/" + libFolderName
        if computer.File(libFolder) != null then
            print("\nSkipping " + libName + " v" + libVersion + " (already scanned)")
            continue
        end if

        computer.create_folder(targetsFolder, libFolderName)

        print("\nScanning " + libName + " v" + libVersion + " on port " + port.port_number)
        output = output + char(10) + char(10) + libName + " v" + libVersion + " on port " + port.port_number

        scanResult = metax.scan(metaLib)
        for zone in scanResult
            memory_scan = metax.scan_address(metaLib, zone)
            print("\nFound memory zone: " + zone)
            output = output + char(10) + char(10) + "Exploits for zone: " + zone

            xpList = memory_scan.split("Unsafe check")[1:]
            exploits = []
            shellExploits = []

            for xp in xpList
                labelStart = xp.indexOf("<b>")
                labelEnd = xp.indexOf("</b>")
                exploit = xp[labelStart + 3: labelEnd]
                print("\nTesting: " + exploit)
                wait(0.5)
                result = metaLib.overflow(zone, exploit, password)

                if result == null then
                    status = "Undefined / Conditional"
                else if typeof(result) == "shell" then
                    user = get_shell_user(result)
                    status = "Shell (" + user + ")"
                    shellExploits.push(exploit)
                else if typeof(result) == "file" then
                    status = "File"
                    if result.path.indexOf("passwd") != -1 or result.path.indexOf("shadow") != -1 then
                        process_passwd_file(result)
                    end if
                else if typeof(result) == "number" then
                    status = "Password: '" + password + "'"
                else if typeof(result) == "computer" then
                    status = "Computer"
                else if typeof(result) == "folder" then
                    status = "Folder"
                else
                    status = "New type: " + typeof(result)
                    if new_types.indexOf(typeof(result)) == null then
                        new_types.push(typeof(result))
                    end if
                end if

                exploits.push(exploit + " (" + status + ")")

                originalName = zone + "_" + exploit
                safeName = ""
                allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                for ch in originalName
                    if allowedChars.indexOf(ch) != null then
                        safeName = safeName + ch
                    else if ch == " " then
                        safeName = safeName + "_"
                    end if
                end for
                safeName = safeName + ".txt"

                vulnContent = "Library: " + libName + " v" + libVersion + char(10)
                vulnContent = vulnContent + "Port: " + port.port_number + char(10)
                vulnContent = vulnContent + "Zone: " + zone + char(10)
                vulnContent = vulnContent + "Exploit: " + exploit + char(10)
                vulnContent = vulnContent + "Result: " + status + char(10)

                computer.touch(libFolder, safeName)
                libFolderObj = computer.File(libFolder)
                vulnFile = null
                for f in libFolderObj.get_files
                    if f.name == safeName then
                        vulnFile = f
                        break
                    end if
                end for
                if vulnFile != null then
                    vulnFile.set_content(vulnContent)
                else
                    print("<b>Warning: Could not write vuln file: " + safeName + "</b>")
                end if

                wait(0.5)
            end for

            if shellExploits.len > 0 then
                print("\nShell exploits for zone " + zone + ": " + shellExploits.join(", "))
            else
                print("\nNo shell exploits for zone " + zone)
            end if
            output = output + char(10) + exploits.join(char(10))
        end for

        if libName.indexOf("ssh") != null then ssh_scanned = true
        if libName.indexOf("ftp") != null then ftp_scanned = true
        if libName.indexOf("http") != null then http_scanned = true
        if libName.indexOf("sql") != null then sql_scanned = true
        if libName.indexOf("smtp") != null then smtp_scanned = true

        if new_types.len > 0 then
            print("\nNew vulnerability types found: " + new_types.join("\n"))
            output = output + char(10) + char(10) + "New Vulnerability Types:" + char(10) + new_types.join(char(10))
        end if
    end for
end if

computer.touch(targetsFolder, txtName)
targetFolder = computer.File(targetsFolder)
outputFile = null
for f in targetFolder.get_files
    if f.name == txtName then
        outputFile = f
        break
    end if
end for
if outputFile == null then exit("<b>Error: Could not get file handle</b>")
outputFile.set_content(output)

print("\nScan completed.")
print("Summary saved to: " + txtFullPath)

// ================================================================
// --- SUMMARY ---
// ================================================================

print("\n========================================")
print("TARGET SUMMARY: " + ipAddress)
print("========================================")

print("\n--- Open Ports & Services ---")
if openPorts.len == 0 then
    print("No open ports found.")
else
    openInfo = "PORT STATE SERVICE VERSION LAN"
    for port in openPorts
        service_info = router.port_info(port)
        lan_ips = port.get_lan_ip
        openInfo = openInfo + "\n" + port.port_number + " open " + service_info + " " + lan_ips
    end for
    print(format_columns(openInfo))
end if

// --- Filtered Shell Exploits Summary (only target's services) ---
print("\n--- Shell Exploits Found (filtered to target's services) ---")
shellCount = 0
targetFolderObj = computer.File(targetsFolder)

targetLibNames = []
if discoveredServices != null and discoveredServices.len > 0 then
    for svc in discoveredServices
        targetLibNames.push(svc.name + "_v" + svc.version)
        targetLibNames.push(svc.name + "_" + svc.version)
    end for
end if

if routerVersion != null then
    targetLibNames.push("kernel_router.so_v" + routerVersion)
end if

if targetLibNames.len == 0 then
    print("  No target services discovered.")
else
    if targetFolderObj != null and targetFolderObj.is_folder then
        for libDir in targetFolderObj.get_folders
            libMatchesTarget = false
            for targetName in targetLibNames
                if libDir.name == targetName then
                    libMatchesTarget = true
                    break
                end if
            end for
            if not libMatchesTarget then
                continue
            end if
            
            files = libDir.get_files
            if files != null and typeof(files) == "list" then
                for f in files
                    content = f.get_content
                    if content == null then continue
                    isShell = false
                    for line in content.split(char(10))
                        if line.indexOf("Result: Shell") == 0 then
                            isShell = true
                            break
                        end if
                    end for
                    if isShell then
                        shellCount = shellCount + 1
                        print("[Shell] " + libDir.name + " / " + f.name)
                    end if
                end for
            end if
        end for
    end if
end if

if shellCount == 0 then
    print("  No shell exploits found for target's services.")
else
    print("  Total shell exploits: " + shellCount)
end if

print("========================================")

// ================================================================
// --- ATTACK PHASE (with port override and result display) ---
// ================================================================

attackChoice = user_input("Launch attack? (y/n): ")
if attackChoice != "y" then exit("Goodbye!")

targetsFolderObj = computer.File(targetsFolder)
if targetsFolderObj == null then
    print("[*] Creating /targets folder...")
    computer.create_folder("/", "targets")
    targetsFolderObj = computer.File(targetsFolder)
end if

if targetsFolderObj == null then
    print("<b>Error: Could not create /targets folder. Aborting attack.</b>")
    exit("Goodbye!")
end if

if not targetsFolderObj.is_folder then
    print("<b>Error: /targets exists but is not a folder.</b>")
    exit("Goodbye!")
end if

// --- Build list of target library names ---
targetLibNames = []
if discoveredServices != null and discoveredServices.len > 0 then
    for svc in discoveredServices
        targetLibNames.push(svc.name + "_v" + svc.version)
        targetLibNames.push(svc.name + "_" + svc.version)
    end for
end if
if routerVersion != null then
    targetLibNames.push("kernel_router.so_v" + routerVersion)
end if

// --- Iterate over all folders and add those that match targetLibNames ---
libFolders = []
libFolderNames = []
folderList = targetsFolderObj.get_folders
if folderList != null and typeof(folderList) == "list" then
    for f in folderList
        if f.is_folder then
            matched = false
            for tname in targetLibNames
                if f.name == tname then
                    matched = true
                    break
                end if
            end for
            if matched then
                libFolders.push(f)
                libFolderNames.push(f.name)
                print("[*] Added: " + f.name)
            end if
        end if
    end for
end if

if libFolders.len == 0 then
    print("<b>Warning: No matching libraries found for target's services.</b>")
    print("[*] Falling back to showing all available libraries.")
    for f in folderList
        if f.is_folder then
            libFolders.push(f)
            libFolderNames.push(f.name)
        end if
    end for
    if libFolders.len == 0 then
        print("<b>No exploit folders found in /targets/</b>")
        print("[*] You need to scan a target first to generate exploit data.")
        exit("Goodbye!")
    end if
end if

// --- Main attack loop ---
while true
    print("\n--- Available Libraries (target's running services) ---")
    i = 0
    for name in libFolderNames
        print("[" + i + "] " + name)
        i = i + 1
    end for
    print("[s] SSH direct login")
    print("[h] Harvest LAN (skips Guest)")
    print("[q] Quit")
    libChoice = user_input("Pick a library or command: ")
    if libChoice == "" then continue
    if libChoice == "q" then exit("Goodbye!")

    if libChoice == "s" then
        sshUser = user_input("SSH username: ")
        sshPass = user_input("SSH password: ")
        sshPort = user_input("SSH port (leave blank for 22): ")
        if sshPort == "" then sshPort = "22"
        print("\nConnecting via SSH to " + ipAddress + ":" + sshPort + " as " + sshUser + "...")
        tgt_shell = shell.connect_service(ipAddress, val(sshPort), sshUser, sshPass, "ssh")
        if not tgt_shell then
            print("<b>SSH login failed. Check credentials.</b>")
            continue
        end if
        print("<b>SSH login successful! Dropping you in...</b>")
        wait(0.5)
        tgt_comp = tgt_shell.host_computer
        tgt_shell.start_terminal
        print("\nCleaning up...")
        ssh_session = metax.net_use(ipAddress, val(sshPort))
        if ssh_session != null and ssh_session.is_root_active_user then
            log_file = tgt_comp.File("/var/system.log")
            if log_file != null and log_file.has_permission("w") then
                log_file.delete
                tgt_comp.touch("/var", "system.log")
                wait(0.2)
                print("Target logs cleared!")
                tgt_shell.launch("/usr/bin/LogViewer.exe")
                print("LogViewer opened on target - check it now!")
                wait(3)
            else
                print("Could not clear logs (no write permission)")
            end if
        else
            print("Not root - logs not cleared.")
        end if
        print("\nAll done!")
        exit("Done!")
    end if

    libIndex = val(libChoice)
    if libIndex == null or libIndex < 0 or libIndex >= libFolders.len then
        print("<b>Invalid choice, try again.</b>")
        continue
    end if

    selectedLib = libFolders[libIndex]
    libName = libFolderNames[libIndex]
    print("\nSelected library: " + libName)

    libParts = libName.split("_v")
    parsedLib = libParts[0]
    parsedVersion = ""
    if libParts.len > 1 then parsedVersion = libParts[1]

    while true
        if not selectedLib.is_folder then
            print("<b>Error: selected library is not a folder.</b>")
            break
        end if

        // Build exploit list with result info
        vulnFiles = []
        vulnFileNames = []
        vulnResults = []
        files = selectedLib.get_files
        if files != null and typeof(files) == "list" then
            for f in files
                content = f.get_content
                if content == null then continue
                // Parse result line
                result_line = ""
                for line in content.split(char(10))
                    if line.indexOf("Result: ") == 0 then
                        result_line = line[8:]
                        break
                    end if
                end for
                if result_line == "" then
                    result_line = "Unknown"
                end if
                vulnFiles.push(f)
                vulnFileNames.push(f.name)
                vulnResults.push(result_line)
            end for
        end if

        if vulnFiles.len == 0 then
            print("<b>No exploit files found in " + libName + ". Going back.</b>")
            break
        end if

        print("\n--- Exploits in " + libName + " ---")
        i = 0
        for name in vulnFileNames
            print("[" + i + "] " + name + " (" + vulnResults[i] + ")")
            i = i + 1
        end for
        print("[b] Back to library picker")
        print("[q] Quit")
        exploitChoice = user_input("Pick an exploit: ")
        if exploitChoice == "" then continue
        if exploitChoice == "q" then exit("Goodbye!")
        if exploitChoice == "b" then break

        exploitIndex = val(exploitChoice)
        if exploitIndex == null or exploitIndex < 0 or exploitIndex >= vulnFiles.len then
            print("<b>Invalid choice, try again.</b>")
            continue
        end if

        print("\nSelected exploit: " + vulnFileNames[exploitIndex] + " (" + vulnResults[exploitIndex] + ")")

        vulnFile = vulnFiles[exploitIndex]
        vulnData = vulnFile.get_content

        zone = ""
        exploit = ""
        port = ""
        for line in vulnData.split(char(10))
            if line.indexOf("Zone: ") == 0 then zone = line[6:]
            if line.indexOf("Exploit: ") == 0 then exploit = line[9:]
            if line.indexOf("Port: ") == 0 then port = line[6:]
        end for

        // Trim port to remove any whitespace or newline characters
        port = port.trim

        if zone == "" or exploit == "" or port == "" then
            print("<b>Error: Could not parse vuln file. Skipping.</b>")
            continue
        end if

        // --- Firing exploit with port override ---
        print("\n--- Firing exploit ---")
        print("Library : " + parsedLib + " v" + parsedVersion)
        print("Zone    : " + zone)
        print("Exploit : " + exploit)
        print("Default port: " + port)
        print("Enter port (press Enter to use default): ")
        portInput = user_input
        if portInput != "" then
            port = portInput.trim
        end if
        // Ensure port is a number
        if port == "" then port = "0"
        portNum = port.to_int
        if portNum == null then
            print("<b>Error: Invalid port number. Using default 0.</b>")
            portNum = 0
        end if
        print("Using port: " + portNum)
        print("")
        wait(0.5)

        if portNum == 0 then
            print("Target  : router (" + ipAddress + " port 0)")
            net_session = metax.net_use(ipAddress, 0)
        else
            net_session = metax.net_use(ipAddress, portNum)
        end if

        if not net_session then
            print("<b>Error: Could not connect. Try a different exploit.</b>")
            continue
        end if

        metaLib = net_session.dump_lib
        result = metaLib.overflow(zone, exploit, password)

        if result == null then
            print("<b>Exploit failed. Falling back to exploit picker...</b>")
            wait(0.5)
            continue
        else if typeof(result) == "shell" then
            print("<b>Shell obtained on " + ipAddress + "! Dropping you in...</b>")
            print("<b>Do your thing. When you are done type exit to clean up and leave.</b>")
            wait(0.5)
            tgt_shell = result
            tgt_comp = tgt_shell.host_computer
            if portNum == 0 then
            print("\nCleaning up...")
            if net_session.is_root_active_user then
                log_file = tgt_comp.File("/var/system.log")
                if log_file != null and log_file.has_permission("w") then
                    log_file.delete
                    tgt_comp.touch("/var", "system.log")
                    wait(0.2)
                    print("Target logs cleared!")
                    tgt_shell.launch("/usr/bin/LogViewer.exe")
                    print("LogViewer opened on target - check it now!")
                    wait(5)
                else
                    print("Could not clear logs (no write permission)")
                end if
            else
                print("Not root - logs not cleared.")
            end if
            print("\nAll done!")
            exit("Done!")
        else if typeof(result) == "firewall" then
            print("Result: Firewall rule obtained!")
            print(result)
            wait(0.5)
            continue
        else if typeof(result) == "number" then
            print("Result: Password cracked! Password is '" + password + "'")
            wait(0.5)
            continue
        else if typeof(result) == "file" then
            print("Result: File access obtained on " + ipAddress + "!")
            print("File: " + result.path)
            if result.path.indexOf("passwd") != -1 or result.path.indexOf("shadow") != -1 then
                process_passwd_file(result)
            end if
            wait(0.5)
            continue
        else if typeof(result) == "computer" then
            print("Result: Computer access obtained on " + ipAddress + "!")
            wait(0.5)
            continue
        else
            print("<b>Exploit failed (" + typeof(result) + "). Falling back to exploit picker...</b>")
            wait(0.5)
            continue
        end if
    end while
end while
