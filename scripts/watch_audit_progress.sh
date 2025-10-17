#!/bin/bash

# AETHER AUDIT MONITOR v7 - Zero-Flicker In-Place Updates
# Uses carriage returns to update lines smoothly without clearing
# Usage: ./watch_audit_progress.sh [refresh_interval]

DB_PATH="$HOME/.aether/aether_github_audit.db"
REFRESH_INTERVAL=${1:-1}
RUNNING=true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

trap "RUNNING=false; tput cnorm; echo ''; echo -e '${GREEN}Monitor stopped${NC}'; exit 0" SIGINT

check_db() {
    if [ ! -f "$DB_PATH" ]; then
        echo -e "${RED}❌ Database not found at $DB_PATH${NC}"
        exit 1
    fi
}

get_db_stat() {
    sqlite3 "$DB_PATH" "$1" 2>/dev/null || echo "0"
}

make_bar() {
    local filled=$1 total=$2 width=22
    [ $total -eq 0 ] && { printf "[%-${width}s]" ""; return; }
    local percent=$((filled * 100 / total))
    local bar_filled=$((filled * width / total))
    local bar=""
    for ((i=0; i<bar_filled; i++)); do bar+="█"; done
    for ((i=bar_filled; i<width; i++)); do bar+="░"; done
    printf "[%s] %3d%%" "$bar" "$percent"
}

update_line() {
    printf '\r%-90s\r%s' "" "$1"
}

# Main loop
check_db
tput civis  # Hide cursor
clear

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BOLD}  🔍 AETHER AUDIT MONITOR - Real-Time Dashboard${NC}${CYAN}                                 ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

TIME_LINE=3
STATS_LINE=$((TIME_LINE + 1))
AUDITS_HEADER=$((STATS_LINE + 2))

while $RUNNING; do
    # Move cursor to time line and update
    tput cuu $(($(tput lines) - TIME_LINE - 1))
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    update_line "${WHITE}[${timestamp}]${NC} Polling: ${BOLD}${REFRESH_INTERVAL}s${NC}"
    echo ""
    
    # Stats line
    local successful=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='success';")
    local failed=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    local skipped=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='skipped';")
    local total=$((successful + failed + skipped))
    local findings=$(get_db_stat "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0) FROM analysis_results WHERE status='success';")
    
    update_line "${CYAN}📊${NC} ✅ $successful | ❌ $failed | ⏭️ $skipped | Total: $total | 🎯 $findings"
    echo ""
    echo ""
    
    # Active Audits
    echo -e "${CYAN}📦 ACTIVE AUDITS${NC}"
    local projects=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT p.id, p.repo_name, s.id, s.total_selected, s.total_audited, s.total_pending
         FROM projects p
         LEFT JOIN audit_scopes s ON p.id = s.project_id AND s.status = 'active'
         WHERE EXISTS (SELECT 1 FROM audit_scopes WHERE project_id = p.id)
         ORDER BY p.id DESC LIMIT 3;" 2>/dev/null)
    
    if [ -z "$projects" ]; then
        echo "(No active audits)"
    else
        while IFS='|' read -r pid repo_name scope_id sel audited pending; do
            if [ -n "$scope_id" ]; then
                local scope_findings=$(get_db_stat "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0) FROM analysis_results ar WHERE ar.contract_id IN (SELECT id FROM contracts WHERE project_id = $pid) AND ar.status = 'success';")
                printf "  %-25s " "$repo_name #$scope_id:"
                make_bar "$audited" "$sel"
                printf " %2d/%2d | %2d findings\n" "$audited" "$sel" "$scope_findings"
            fi
        done <<< "$projects"
    fi
    echo ""
    
    # Recent Activity
    echo -e "${CYAN}⚡ RECENT (60s)${NC}"
    local recent=$(sqlite3 "$DB_PATH" \
        "SELECT c.file_path, ar.status, json_extract(ar.findings, '$.total_findings') as findings, 
                printf('%.1f', ar.analysis_duration_ms/1000.0) as duration
         FROM analysis_results ar
         JOIN contracts c ON ar.contract_id = c.id
         WHERE ar.analysis_type='enhanced'
         AND datetime(ar.created_at) > datetime('now', '-60 seconds')
         ORDER BY ar.created_at DESC LIMIT 4;" 2>/dev/null)
    
    if [ -z "$recent" ]; then
        echo "(No recent activity)"
    else
        local count=1
        while IFS='|' read -r contract status findings duration; do
            name=$(basename "$contract")
            case "$status" in
                "success")
                    [ "$findings" != "0" ] && [ "$findings" != "" ] && \
                        printf "  %-2d. %-40s [%2d findings] %4.1fs\n" "$count" "$name" "$findings" "$duration" || \
                        printf "  %-2d. %-40s [clean] %4.1fs\n" "$count" "$name" "$duration"
                    ;;
                *)
                    printf "  %-2d. %-40s [$status]\n" "$count" "$name"
                    ;;
            esac
            count=$((count + 1))
        done <<< "$recent"
    fi
    echo ""
    
    # Summary
    local active=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='active';")
    local completed=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='completed';")
    local proj_count=$(get_db_stat "SELECT COUNT(DISTINCT id) FROM projects;")
    echo -e "${CYAN}📋${NC} Active: $active | Done: $completed | Projects: $proj_count"
    
    # Errors
    local err_count=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    if [ "$err_count" -gt 0 ]; then
        echo ""
        echo -e "${RED}⚠️ ERRORS ($err_count)${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    sleep "$REFRESH_INTERVAL"
done

tput cnorm  # Show cursor
