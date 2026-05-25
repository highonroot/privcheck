#!/bin/bash

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

SHOW_FIX=false
FINDINGS=0

if [ "$1" = "--fix" ]; then
    SHOW_FIX=true
fi

check_identity() {
    echo "[*] Checking identity..."

    id_op=$(id)
    current_user=$(whoami)
    id_found=false

    echo "    User: $current_user"
    echo "    $id_op"
    echo ""

    dang_groups=("sudo" "docker" "adm" "shadow" "disk")

    user_groups=$(id -nG)

    for group in "${dang_groups[@]}"; do
        for actual in $user_groups; do
            if [ "$actual" = "$group" ]; then
                echo -e "${RED}[+] Found (Identity): member of '$group' group — potential privilege escalation${NC}"
                FINDINGS=$((FINDINGS + 1))
                id_found=true

                if [ "$SHOW_FIX" = true ]; then
                    echo "    Fix: remove user from privileged group"
                    echo "         sudo gpasswd -d $current_user $group"
                    echo "    Verify: id $current_user"
                fi
                break
            fi
        done
    done

    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${YELLOW}[!] Running as root — no escalation needed${NC}"
    fi

    if [ "$id_found" = false ]; then
        echo -e "${GREEN}[-] Identity: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_sudo() {
    echo "[*] Checking sudo settings..."

    sudo_op=$(sudo -l 2>/dev/null)
    sudo_flags=("NOPASSWD" "env_keep")
    sudo_found=false

    for flag in "${sudo_flags[@]}"; do
        if echo "$sudo_op" | grep -q "$flag"; then
            echo -e "${RED}[+] Found (Sudo): $flag detected — check sudoers${NC}"
            FINDINGS=$((FINDINGS + 1))
            sudo_found=true

            if [ "$SHOW_FIX" = true ]; then
                echo "    Fix: edit sudoers safely"
                echo "         sudo visudo"
                echo "         remove or restrict $flag entries"
                echo "    Verify: sudo -l"
            fi
        fi
    done

    if [ "$sudo_found" = false ]; then
        echo -e "${GREEN}[-] Sudo: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_suid_sgid() {
    echo "[*] Checking SUID/SGID binaries..."

    suid_op=$(find / -perm -u=s -type f 2>/dev/null)
    found_suid=false

    dangerous_names=("vim" "vi" "nano" "find" "python" "python3" "perl" "bash" "sh" "dash" "cp" "mv" "tar" "curl" "wget" "nmap" "env" "less" "more" "awk")
    standard_paths=("/usr/bin" "/bin" "/usr/sbin" "/sbin")

    while IFS= read -r binary; do        
        [ -z "$binary" ] && continue
        flagged=false

        if [ -w "$binary" ]; then
            echo -e "${RED}[+] Found (SUID): writable SUID binary — $binary${NC}"
            FINDINGS=$((FINDINGS + 1))
            found_suid=true
            flagged=true
        fi

        binary_dir=$(dirname "$binary")
        in_standard=false
        for std in "${standard_paths[@]}"; do
            if [ "$binary_dir" = "$std" ]; then
                in_standard=true
                break
            fi
        done

        if [ "$in_standard" = false ] && [ "$flagged" = false ]; then
            echo -e "${RED}[+] Found (SUID): SUID binary outside standard path — $binary${NC}"
            FINDINGS=$((FINDINGS + 1))
            found_suid=true
            flagged=true
        fi

        binary_name=$(basename "$binary")
        for danger in "${dangerous_names[@]}"; do
            if [ "$binary_name" = "$danger" ] && [ "$flagged" = false ]; then
                echo -e "${RED}[+] Found (SUID): dangerous binary with SUID — $binary${NC}"
                FINDINGS=$((FINDINGS + 1))
                found_suid=true
                flagged=true
                break
            fi
        done

        if [ "$flagged" = true ] && [ "$SHOW_FIX" = true ]; then
            echo "    Fix: remove SUID bit"
            echo "         sudo chmod u-s $binary"
            echo "    Verify: ls -la $binary"
        fi

    done <<< "$suid_op"

    if [ "$found_suid" = false ]; then
        echo -e "${GREEN}[-] SUID: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_capabilities() {
    echo "[*] Checking capabilities..."

    cap_op=$(getcap -r / 2>/dev/null)
    cap_set=false

    for cap in "cap_setuid" "cap_dac_override" "cap_sys_admin"; do
        if echo "$cap_op" | grep -q "$cap"; then
            matching=$(echo "$cap_op" | grep "$cap")
            echo -e "${RED}[+] Found (Capability): $cap detected — $matching${NC}"
            FINDINGS=$((FINDINGS + 1))
            cap_set=true

            if [ "$SHOW_FIX" = true ]; then
                binary=$(echo "$matching" | awk '{print $1}')
                echo "    Fix: remove capability from binary"
                echo "         sudo setcap -r $binary"
                echo "    Verify: getcap -r / 2>/dev/null"
            fi
        fi
    done

    if [ "$cap_set" = false ]; then
        echo -e "${GREEN}[-] Capabilities: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_cron() {
    echo "[*] Checking crontab..."

    writable_cronfiles=$(find /etc/cron* -writable -type f 2>/dev/null)
    writable_crondirs=$(find /etc/cron* -writable -type d 2>/dev/null)
    cron_found=false

    relative_cmds=""
    if [ -f /etc/crontab ]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^[A-Z_]+=.* ]] && continue

            cmd=$(echo "$line" | awk '{print $7}')
            if [ -n "$cmd" ] && [[ "$cmd" != /* ]]; then
                relative_cmds="$relative_cmds\n$line"
            fi
        done < /etc/crontab
    fi
    
    if [ -n "$writable_cronfiles" ]; then
        echo -e "${RED}[+] Found (Cron): writable cron scripts detected${NC}"
        echo "$writable_cronfiles"
        FINDINGS=$((FINDINGS + 1))
        cron_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restrict cron script permissions"
            echo "         sudo chmod 700 <script>"
            echo "         sudo chown root:root <script>"
            echo "    Verify: ls -la /etc/cron*"
        fi
    fi

    if [ -n "$writable_crondirs" ]; then
        echo -e "${RED}[+] Found (Cron): writable cron directory detected${NC}"
        echo "$writable_crondirs"
        FINDINGS=$((FINDINGS + 1))
        cron_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restrict cron directory permissions"
            echo "         sudo chmod 755 /etc/cron*"
            echo "    Verify: ls -la /etc/cron*"
        fi
    fi

    if [ -n "$relative_cmds" ]; then
        echo -e "${RED}[+] Found (Cron): relative commands detected in crontab${NC}"
        echo -e "$relative_cmds"
        FINDINGS=$((FINDINGS + 1))
        cron_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: use absolute paths in cron scripts"
            echo "         replace 'tar' with '/usr/bin/tar'"
            echo "    Verify: cat /etc/crontab"
        fi
    fi

    if [ "$cron_found" = false ]; then
        echo -e "${GREEN}[-] Cron: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_writable() {
    echo "[*] Checking writables..."

    writable_rbins=$(find / -writable -type f -user root 2>/dev/null | grep -v "^/tmp\|^/proc\|^/sys\|^/dev\|^/home")
    writable_dirs=$(find / -writable -type d 2>/dev/null | grep -v "^/tmp\|^/proc\|^/sys\|^/dev\|^/run\|^/home")
    writable_scripts=$(find / -writable -name "*.sh" 2>/dev/null | grep -v "^/tmp\|^/proc\|^/sys\|^/dev")
    writable_found=false

    if [ -n "$writable_rbins" ]; then
        echo -e "${RED}[+] Found (Writables): root-owned writable files detected${NC}"
        echo "$writable_rbins"
        FINDINGS=$((FINDINGS + 1))
        writable_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restore correct ownership and permissions"
            echo "         sudo chown root:root <file>"
            echo "         sudo chmod 644 <file>  (or 755 for executables)"
            echo "    Verify: ls -l <file>"
        fi
    fi

    if [ -n "$writable_dirs" ]; then
        echo -e "${RED}[+] Found (Writables): suspicious writable directories detected${NC}"
        echo "$writable_dirs"
        FINDINGS=$((FINDINGS + 1))
        writable_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restrict directory permissions"
            echo "         sudo chmod 755 <directory>"
            echo "    Verify: ls -la <directory>"
        fi
    fi

    if [ -n "$writable_scripts" ]; then
        echo -e "${RED}[+] Found (Writables): writable scripts detected${NC}"
        echo "$writable_scripts"
        FINDINGS=$((FINDINGS + 1))
        writable_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restrict script permissions"
            echo "         sudo chmod 700 <script>"
            echo "         sudo chown root:root <script>"
            echo "    Verify: ls -l <script>"
        fi
    fi

    if [ "$writable_found" = false ]; then
        echo -e "${GREEN}[-] Writables: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_path() {
    echo "[*] Checking PATH variable..."

    real_path=("/usr/bin" "/usr/sbin" "/bin" "/sbin" "/usr/local/sbin" "/usr/local/bin")
    path_found=false

    IFS=: read -ra path_entries <<< "$PATH"
    for entry in "${path_entries[@]}"; do
        in_real=false
        for std in "${real_path[@]}"; do
            if [ "$entry" = "$std" ]; then
                in_real=true
                break
            fi
        done

        if [ "$in_real" = false ] && [ -w "$entry" ]; then
            echo -e "${RED}[+] Found (PATH): writable non-standard directory in PATH — $entry${NC}"
            FINDINGS=$((FINDINGS + 1))
            path_found=true

            if [ "$SHOW_FIX" = true ]; then
                echo "    Fix: remove writable directories from PATH configuration"
                echo "    Verify: echo \$PATH"
            fi
        fi
    done

    if [ "$path_found" = false ]; then
        echo -e "${GREEN}[-] PATH: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_credentials() {
    echo "[*] Checking credentials..."

    pass_in_history=$(grep -i "pass\|password\|passwd" ~/.bash_history 2>/dev/null)
    creds_in_env=$(env | grep -iE "key|token|pass|secret|api")
    pass_in_confs=$(find / -name "*.conf" -o -name "*.env" 2>/dev/null | xargs grep -l "password" 2>/dev/null)
    readable_ssh=$(find ~/.ssh -name "id_rsa" -readable 2>/dev/null)
    creds_found=false

    if [ -n "$pass_in_history" ]; then
        echo -e "${RED}[+] Found (Credentials): password strings detected in shell history${NC}"
        echo "$pass_in_history"
        FINDINGS=$((FINDINGS + 1))
        creds_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: clear shell history"
            echo "         history -c"
            echo "         Note: clearing history doesn't undo exposure"
            echo "               rotate any credentials that appeared in history"
            echo "    Verify: cat ~/.bash_history"
        fi
    fi

    if [ -n "$creds_in_env" ]; then
        echo -e "${YELLOW}[!] Review (Credentials): sensitive strings found in environment variables${NC}"
        echo "$creds_in_env"
        creds_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Note: environment variables may be legitimately set"
            echo "    Fix if exposed: unset VARIABLE_NAME"
            echo "    Verify: env | grep -iE 'key|token|pass|secret'"
        fi
    fi

    if [ -n "$pass_in_confs" ]; then
        echo -e "${RED}[+] Found (Credentials): password strings in config files${NC}"
        echo "$pass_in_confs"
        FINDINGS=$((FINDINGS + 1))
        creds_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: remove hardcoded credentials from config files"
            echo "         use environment variables or secrets manager instead"
            echo "         rotate any exposed credentials immediately"
            echo "    Verify: grep -r 'password' /etc 2>/dev/null"
        fi
    fi

    if [ -n "$readable_ssh" ]; then
        echo -e "${RED}[+] Found (Credentials): SSH private key readable${NC}"
        echo "$readable_ssh"
        FINDINGS=$((FINDINGS + 1))
        creds_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restrict private key permissions"
            echo "         chmod 600 ~/.ssh/id_rsa"
            echo "    Verify: ls -la ~/.ssh/"
        fi
    fi

    if [ "$creds_found" = false ]; then
        echo -e "${GREEN}[-] Credentials: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_sensitive() {
    echo "[*] Checking sensitive files..."

    sensitive_found=false

    passwd_perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
    group_perms=$(stat -c "%a" /etc/group 2>/dev/null)
    shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)

    passwd_others=${passwd_perms: -1}
    if [[ "$passwd_others" =~ [2367] ]]; then
        echo -e "${RED}[+] Found (Sensitive): /etc/passwd writable by others — permissions: $passwd_perms${NC}"
        FINDINGS=$((FINDINGS + 1))
        sensitive_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: sudo chmod 644 /etc/passwd"
            echo "    Verify: ls -l /etc/passwd"
        fi
    fi

    group_others=${group_perms: -1}
    if [[ "$group_others" =~ [2367] ]]; then
        echo -e "${RED}[+] Found (Sensitive): /etc/group writable by others — permissions: $group_perms${NC}"
        FINDINGS=$((FINDINGS + 1))
        sensitive_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: sudo chmod 644 /etc/group"
            echo "    Verify: ls -l /etc/group"
        fi
    fi

    shadow_others=${shadow_perms: -1}
    if [ -n "$shadow_perms" ] && [ "$shadow_others" -gt 0 ]; then
        echo -e "${RED}[+] Found (Sensitive): /etc/shadow accessible by others — permissions: $shadow_perms${NC}"
        FINDINGS=$((FINDINGS + 1))
        sensitive_found=true

        if [ "$SHOW_FIX" = true ]; then
            echo "    Fix: restore default ownership and permissions"
            echo "         sudo chmod 640 /etc/shadow"
            echo "    Verify: ls -l /etc/shadow"
        fi
    fi

    if [ "$sensitive_found" = false ]; then
        echo -e "${GREEN}[-] Sensitive files: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

check_process() {
    echo "[*] Checking processes..."

    procs_found=false

    while IFS= read -r proc_binary; do
        [ -z "$proc_binary" ] && continue
        [ ! -f "$proc_binary" ] && continue

        if [ -w "$proc_binary" ]; then
            echo -e "${RED}[+] Found (Process): root process running writable binary — $proc_binary${NC}"
            FINDINGS=$((FINDINGS + 1))
            procs_found=true

            if [ "$SHOW_FIX" = true ]; then
                echo "    Fix: restrict binary permissions"
                echo "         sudo chmod 755 $proc_binary"
                echo "         sudo chown root:root $proc_binary"
                echo "    Verify: ls -la $proc_binary"
            fi
        fi
    done <<< "$(ps aux | grep "^root" | awk '{for(i=11;i<=NF;i++) print $i}' | sort -u 2>/dev/null)"

    open_ports=$(ss -tlnp 2>/dev/null)
    if [ -n "$open_ports" ]; then
        echo -e "${YELLOW}[!] Open ports and listening services:${NC}"
        echo "$open_ports"
    fi

    if [ "$procs_found" = false ]; then
        echo -e "${GREEN}[-] Processes: nothing suspicious${NC}"
    fi

    echo ""
    sleep 0.5
}

echo "Analyzing system..."
echo ""
sleep 0.5

check_identity
check_sudo
check_suid_sgid
check_capabilities
check_cron
check_writable
check_path
check_credentials
check_sensitive
check_process

echo ""
echo "Flagged findings: $FINDINGS"
echo ""

if [ "$FINDINGS" -ne 0 ] && [ "$SHOW_FIX" = false ]; then
    echo -e "${YELLOW}[!] Run ./privcheck.sh --fix for remediation guidance"
    echo -e "    See: https://github.com/highonroot/ctf-writeups/blob/main/linux-privesc/12-hardening-guide.md${NC}"
    
elif [ "$FINDINGS" -ne 0 ] && [ "$SHOW_FIX" = true ]; then
    echo -e "${YELLOW}[!] Review fixes above and verify changes${NC}"
    
else
    echo -e "${GREEN}[-] No potential escalation paths found.${NC}"
    echo -e "${YELLOW}[!] NOTE: Clean output does not guarantee a fully hardened system."
    echo -e "    Run periodically and after any system changes.${NC}"
fi
