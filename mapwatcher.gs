// mapwatcher v1.2 - FOR MAPKIT+DAEMONMAIL! Launches mapkit after queue.txt gets dropped in your exploit server by daemonmail! NOT A STANDALONE!
print("=" * 50)
print("MapWatcher v1.2")
print("=" * 50)

shell = get_shell
computer = shell.host_computer
queueFile = "/targets/queue.txt"
lockFile = "/targets/queue.lock"
doneFile = "/targets/queue.done"

// Setup dirs
if computer.File("/targets") == null then
    computer.create_folder("/", "targets")
end if

// -------------------- HELPERS --------------------
load_list = function(path)
    list = []
    f = computer.File(path)
    if f == null then
        print("File not found: " + path)
        return list
    end if
    content = f.get_content
    if content == null then
        print("File content is null for " + path)
        return list
    end if
    if content.trim == "" then
        print("File is empty for " + path)
        return list
    end if
    print("Raw content of " + path + ": '" + content + "'")
    for line in content.split("\n")
        line = line.trim
        if line != "" then
            list.push(line)
            print("Added line: '" + line + "'")
        end if
    end for
    return list
end function

save_list = function(path, list)
    f = computer.File(path)
    if f == null then
        parts = path.split("/")
        fname = parts[-1]
        fdir = path[:path.len - fname.len - 1]
        computer.touch(fdir, fname)
        f = computer.File(path)
    end if
    if f != null then
        f.set_content(list.join("\n"))
    end if
end function

get_pid_by_cmd = function(cmd_substr)
    if computer.show_procs == null then return null
    rows = computer.show_procs.split(char(10))
    for r in rows
        parts = r.split(" ")
        tokens = []
        for t in parts
            if t != "" then tokens.push(t)
        end for
        if tokens.len >= 5 then
            cmd = tokens[4:].join(" ")
            if cmd.indexOf(cmd_substr) != null then
                pid = val(tokens[1])
                if pid != null then return pid
            end if
        end if
    end for
    return null
end function

is_pid_alive = function(pid)
    if pid == null then return false
    if computer.show_procs == null then return false
    rows = computer.show_procs.split(char(10))
    for r in rows
        parts = r.split(" ")
        tokens = []
        for t in parts
            if t != "" then tokens.push(t)
        end for
        if tokens.len >= 2 and tokens[1] == pid then
            return true
        end if
    end for
    return false
end function

// -------------------- MAIN LOOP --------------------
print("[Watcher] mapkit found at: /bin/mapkit")
print("[Watcher] Watching queue: " + queueFile)
print("[Watcher] Ready.")
print("")

while true
    // --- Check lock file ---
    lFile = computer.File(lockFile)
    if lFile != null then
        content = lFile.get_content
        if content != null and content.trim != "" then
            pid = content.trim.to_int
            if pid != null and is_pid_alive(pid) then
                print("[Watcher] Mapkit (PID " + pid + ") running - waiting...")
                wait(15)
                continue
            else
                print("[Watcher] Stale lock found (PID " + pid + " not running) - clearing")
                lFile.delete
            end if
        else
            print("[Watcher] Empty lock file – clearing")
            lFile.delete
        end if
    end if

    // --- Check queue ---
    print("Checking queue file...")
    queue = load_list(queueFile)
    print("Queue length = " + queue.len)
    if queue.len == 0 then
        print("[Watcher] Queue empty, waiting...")
        wait(15)
        continue
    end if

    // --- Get next job ---
    target_ip = queue[0]
    queue.remove(0)
    save_list(queueFile, queue)
    print("\n[Watcher] New job: " + target_ip)

    // --- Check already done ---
    done = load_list(doneFile)
    if done.indexOf(target_ip) != null then
        print("[Watcher] Already completed: " + target_ip + " - skipping")
        continue
    end if

    // --- Check results already exist ---
    if computer.File("/targets/" + target_ip + ".txt") != null then
        print("[Watcher] Results already exist for: " + target_ip + " - skipping")
        done.push(target_ip)
        save_list(doneFile, done)
        continue
    end if

    // --- Launch mapkit ---
    print("[Watcher] Firing mapkit for: " + target_ip)
    shell.launch("/usr/bin/Terminal.exe", "/bin/mapkit " + target_ip)

    wait(2)
    mapkit_pid = get_pid_by_cmd("mapkit")
    if mapkit_pid == null then
        print("[Watcher] Warning: Could not get PID of mapkit process – using fallback")
        computer.touch("/targets", "queue.lock")
        lFile = computer.File(lockFile)
        if lFile != null then lFile.set_content(target_ip)
    else
        computer.touch("/targets", "queue.lock")
        lFile = computer.File(lockFile)
        if lFile != null then lFile.set_content(mapkit_pid)
        print("[Watcher] Mapkit launched with PID: " + mapkit_pid)
    end if

    waited = 0
    maxWait = 360
    while waited < maxWait
        wait(10)
        waited = waited + 10
        if computer.File("/targets/" + target_ip + ".txt") != null then
            print("[Watcher] Mapkit done for: " + target_ip)
            break
        end if
        if mapkit_pid != null and not is_pid_alive(mapkit_pid) and waited > 30 then
            print("[Watcher] Mapkit (PID " + mapkit_pid + ") exited early for: " + target_ip)
            break
        end if
    end while

    if waited >= maxWait then
        print("[Watcher] Timeout for: " + target_ip)
    end if

    done.push(target_ip)
    save_list(doneFile, done)
    lFile = computer.File(lockFile)
    if lFile != null then lFile.delete
    print("[Watcher] Job complete: " + target_ip)
    print("")
end while
