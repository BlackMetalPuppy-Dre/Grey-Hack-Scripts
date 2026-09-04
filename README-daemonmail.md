Mail Automation Daemon

Main Control Flow:
command-line options such as --once, --auto, --interval(removed), and --old-pid. --once(removed) i never use (more debug then function is removed) i always run with --auto (will check terminal PID saves it for after mail scan) 
--interval and --once are removed, and --old-pid is for the auto flag so it can kill the old terminal (because gray hack mail is weird the terminal does not see new mails) thats why the PID kill

At startup, the script:
daemonmail --auto -> gets pid -> scans mail -> que's targets -> launches mapkit with first ip -> tries to harvest banks -> launches mapkit again with qued ip-> tries to harvest bank -> when que empty it waits 10 sec
-> launches new instance daemonmail --auto --old-pid -> new instance -> checks pid -> kills old-pid -> repeats process 
(when no new mails it waits 10 sec so you can ctrl+c or close terminal or it keeps opening daemonmail --auto --old-pid)

use how you want to use it 
Made with,Claude AI(sonnet 4.6), Deepseek, GitHub Copilot, (free versions)
