#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
ARISTA_DIR="$SCRIPT_DIR/Arista"
CONFIG_FILE="$ARISTA_DIR/config.json"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         ARISTA MATRIX SCANNER                ║"
    echo "║         Termux Edition v2.0                  ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() { echo -e "${GREEN}${BOLD}▶ $1${NC}"; }
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ $1${NC}"; }
print_warning() { echo -e "${PURPLE}⚠ $1${NC}"; }
separator() { echo -e "${BLUE}${BOLD}─────────────────────────────────────────────────────${NC}"; }
wait_for_enter() { echo -e "\n${YELLOW}Press Enter to continue...${NC}"; read -r; }

check_dependencies() {
    print_section "Checking Dependencies"
    local missing=()
    
    command -v python3 &> /dev/null || missing+=("python3")
    command -v pip &> /dev/null || missing+=("pip")
    
    if [[ -d "/data/data/com.termux" ]]; then
        print_success "Termux environment detected"
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Missing: ${missing[*]}"
        print_info "Install: pkg install python3 python-pip"
        return 1
    fi
    return 0
}

install_packages() {
    print_section "Installing Python Packages"
    pip install -r "$ARISTA_DIR/requirements.txt" --quiet && print_success "Packages installed" || print_error "Install failed"
}

get_ip_range() {
    print_section "Select IP Range"
    echo -e "  ${CYAN}1.${NC} Private (10.0.0.0/8)"
    echo -e "  ${CYAN}2.${NC} Cloudflare (104.0.0.0/12)"
    echo -e "  ${CYAN}3.${NC} Google (8.8.0.0/16)"
    echo -e "  ${CYAN}4.${NC} All IPv4 (0.0.0.0/0)"
    echo -e "  ${CYAN}5.${NC} Custom"
    read -p "Choice [1-5]: " choice
    
    case $choice in
        1) echo "10.0.0.0/8" ;;
        2) echo "104.0.0.0/12" ;;
        3) echo "8.8.0.0/16" ;;
        4) echo "0.0.0.0/0" ;;
        5) read -p "Enter CIDR: " cidr; echo "$cidr" ;;
        *) echo "10.0.0.0/8" ;;
    esac
}

get_ip_count() {
    print_section "Number of IPs"
    echo -e "  ${CYAN}1.${NC} Fast (100)"
    echo -e "  ${CYAN}2.${NC} Medium (500)"
    echo -e "  ${CYAN}3.${NC} Standard (1000)"
    echo -e "  ${CYAN}4.${NC} Custom"
    read -p "Choice [1-4]: " choice
    
    case $choice in
        1) echo 100 ;;
        2) echo 500 ;;
        3) echo 1000 ;;
        4) read -p "Enter count: " count; echo "$count" ;;
        *) echo 500 ;;
    esac
}

update_config() {
    local cidr_range="$1"
    local ip_count="$2"
    
    print_section "Updating Configuration"
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup"
    
    local batch_size=500
    [[ $ip_count -lt 100 ]] && batch_size=50
    [[ $ip_count -lt 500 ]] && batch_size=100
    [[ $ip_count -gt 2000 ]] && batch_size=1000
    
    local threads=100
    [[ ! -d "/data/data/com.termux" ]] && threads=200
    
    python3 << EOF
import json, ipaddress, random
with open("$CONFIG_FILE", "r") as f: config = json.load(f)
config["batch_size"] = $batch_size
config["threads"] = $threads

ips = []
for cidr in "$cidr_range".split(","):
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = list(net.hosts())
        if len(hosts) > $ip_count:
            hosts = random.sample(hosts, $ip_count)
        ips.extend([str(ip) for ip in hosts])
    except: pass

with open("$SCRIPT_DIR/selected_ips.txt", "w") as f:
    f.write("\n".join(ips[:$ip_count]))

if ips:
    config["sources"] = ["file://$SCRIPT_DIR/selected_ips.txt"]

with open("$CONFIG_FILE", "w") as f:
    json.dump(config, f, indent=4)
print(f"Batch: $batch_size, Threads: $threads")
EOF
    
    print_success "Config updated"
}

run_scanner() {
    local mode="$1"
    print_section "Starting Scanner"
    mkdir -p "$OUTPUT_DIR"
    cd "$ARISTA_DIR"
    
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local start=$(date +%s)
    
    case $mode in
        "full") python3 main.py ;;
        "tcp") python3 main.py --tcp ;;
        "tls") python3 main.py --tls ;;
        "https") python3 main.py --https ;;
        "fp") python3 main.py --fp ;;
        "geo") python3 main.py --geo ;;
        "finalize") python3 main.py --finalize ;;
        *) python3 main.py ;;
    esac
    
    local exit_code=$?
    local duration=$(($(date +%s) - start))
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    cd "$SCRIPT_DIR"
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Completed in ${duration}s"
        show_results
    else
        print_error "Failed with code: $exit_code"
    fi
}

show_results() {
    local best_file="$OUTPUT_DIR/best_ips.txt"
    if [[ -f "$best_file" ]]; then
        print_section "Top 10 Results"
        head -n 10 "$best_file" | while read line; do
            if echo "$line" | grep -q "SCORE=1[0-9]"; then
                echo -e "${GREEN}✓ $line${NC}"
            elif echo "$line" | grep -q "SCORE=[5-9]"; then
                echo -e "${YELLOW}► $line${NC}"
            else
                echo -e "${CYAN}◈ $line${NC}"
            fi
        done
        separator
    fi
}

copy_results() {
    local best_file="$OUTPUT_DIR/best_ips.txt"
    [[ ! -f "$best_file" ]] && print_error "No results" && return
    
    echo -e "  ${CYAN}1.${NC} Copy 10 IPs"
    echo -e "  ${CYAN}2.${NC} Copy 50 IPs"
    echo -e "  ${CYAN}3.${NC} Copy all"
    read -p "Choice: " choice
    
    local content=""
    case $choice in
        1) content=$(head -n 10 "$best_file") ;;
        2) content=$(head -n 50 "$best_file") ;;
        3) content=$(cat "$best_file") ;;
        *) return ;;
    esac
    
    if command -v termux-clipboard-set &> /dev/null; then
        echo "$content" | termux-clipboard-set
        print_success "Copied to clipboard"
    else
        echo "$content"
        print_info "Copy manually"
    fi
}

main_menu() {
    while true; do
        clear
        print_banner
        echo -e "${CYAN}${BOLD}Main Menu${NC}\n"
        echo -e "  ${GREEN}1.${NC} Quick Scan"
        echo -e "  ${GREEN}2.${NC} Custom Scan"
        echo -e "  ${GREEN}3.${NC} TCP Scan"
        echo -e "  ${GREEN}4.${NC} TLS Scan"
        echo -e "  ${GREEN}5.${NC} HTTPS Scan"
        echo -e "  ${GREEN}6.${NC} Fingerprint"
        echo -e "  ${GREEN}7.${NC} GEO Scan"
        echo -e "  ${GREEN}8.${NC} Finalize"
        echo -e "  ${GREEN}9.${NC} View Results"
        echo -e "  ${GREEN}10.${NC} Copy Results"
        echo -e "  ${RED}0.${NC} Exit\n"
        
        read -p "Choice: " choice
        
        case $choice in
            1) update_config "10.0.0.0/8" 500; run_scanner "full"; wait_for_enter ;;
            2) local range=$(get_ip_range); local count=$(get_ip_count); update_config "$range" "$count"; run_scanner "full"; wait_for_enter ;;
            3) run_scanner "tcp"; wait_for_enter ;;
            4) run_scanner "tls"; wait_for_enter ;;
            5) run_scanner "https"; wait_for_enter ;;
            6) run_scanner "fp"; wait_for_enter ;;
            7) run_scanner "geo"; wait_for_enter ;;
            8) run_scanner "finalize"; wait_for_enter ;;
            9) show_results; wait_for_enter ;;
            10) copy_results; wait_for_enter ;;
            0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) print_error "Invalid"; wait_for_enter ;;
        esac
    done
}

initial_setup() {
    clear
    print_banner
    print_section "Initial Setup"
    check_dependencies || exit 1
    install_packages || exit 1
    mkdir -p "$OUTPUT_DIR" "$ARISTA_DIR"
    print_success "Setup complete"
    wait_for_enter
}

[[ -d "/data/data/com.termux" ]] && termux-wake-lock &> /dev/null
initial_setup
main_menu
