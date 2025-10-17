#!/bin/bash

# AETHER AUDIT MONITOR v3 - Advanced Real-Time Monitoring System
# Database-aware polling with smooth ANSI screen updates (no flicker)
# Usage: ./watch_audit_progress.sh [refresh_interval]

DB_PATH="$HOME/.aether/aether_github_audit.db"
REFRESH_INTERVAL=${1:-1}
RUNNING=true
FIRST_RUN=true

# ANSI codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Cursor positioning
HIDE_CURSOR='\033[?25l'
SHOW_CURSOR='\033[?25h'
SAVE_POS='\033[s'
RESTORE_POS='\033[u'

# Trap Ctrl+C to exit gracefully
trap "RUNNING=false; echo -e '${SHOW_CURSOR}'; clear; echo -e '${GREEN}Monitor stopped${NC}'; exit 0" SIGINT

# Check if database exists
check_db() {
    if [ ! -f "$DB_PATH" ]; then
        echo -e "${RED}❌ Database not found at $DB_PATH${NC}"
        exit 1
    fi
}

# Get database stats
get_db_stat() {
    local query="$1"
    sqlite3 "$DB_PATH" "$query" 2>/dev/null || echo "0"
}

# Create progress bar
make_bar() {
    local filled=$1
    local total=$2
    local width=40
    
    if [ $total -eq 0 ]; then
        printf "[%-${width}s] 0/0 (0%%)" ""
        return
    fi
    
    local percent=$((filled * 100 / total))
    local bar_filled=$((filled * width / total))
    local bar_empty=$((width - bar_filled))
    
    local bar="["
    for ((i=0; i<bar_filled; i++)); do bar+="█"; done
    for ((i=0; i<bar_empty; i++)); do bar+="░"; done
    bar+="]"
    
    printf "%s %d/%d (%d%%)" "$bar" "$filled" "$total" "$percent"
}

# Static header (printed once)
print_header() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  🔍 AETHER AUDIT MONITOR - Advanced Real-Time Multi-Project Auditing Dashboard${NC}${CYAN}   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Update header with time (smooth update)
update_header_time() {
    local timestamp=$(date '+%A, %B %d, %Y | %H:%M:%S')
    local uptime=$(uptime | awk -F'up' '{print $2}' | cut -d',' -f1)
    echo -e "${WHITE}${timestamp}${NC} | Polling: ${BOLD}${REFRESH_INTERVAL}s${NC} | ${DIM}Uptime: $(echo $uptime | xargs)${NC}"
}

# Update global stats section
update_global_stats() {
    local successful=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='success';")
    local failed=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    local skipped=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='skipped';")
    local cached=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='cached';")
    local total=$((successful + failed + skipped + cached))
    local findings=$(get_db_stat "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0) FROM analysis_results WHERE status='success';")
    
    echo -e "${CYAN}║${BOLD}  📈 GLOBAL STATISTICS - All Projects Combined${NC}${CYAN}                                 ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "   ${GREEN}✅ Successful: $successful${NC} | ${RED}❌ Failed: $failed${NC} | ${YELLOW}⏭️  Skipped: $skipped${NC} | ${CYAN}⚡ Cached: $cached${NC}"
    echo -e "   ${WHITE}📈 Total Contracts: $total${NC} | ${MAGENTA}🎯 Total Findings: $findings${NC}"
    echo ""
}

# Update active projects section
update_live_projects() {
    echo -e "${CYAN}║${BOLD}  📊 ACTIVE AUDITS - Live Monitoring${NC}${CYAN}                                          ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    
    local projects=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT p.id, p.repo_name, p.url, COUNT(DISTINCT s.id) as scope_count
         FROM projects p
         LEFT JOIN audit_scopes s ON p.id = s.project_id AND s.status = 'active'
         WHERE EXISTS (SELECT 1 FROM audit_scopes WHERE project_id = p.id)
         GROUP BY p.id
         ORDER BY p.id DESC;" 2>/dev/null)
    
    if [ -z "$projects" ]; then
        echo -e "${YELLOW}ℹ️  No audit projects found.${NC}"
        echo ""
        return
    fi
    
    while IFS='|' read -r project_id repo_name url scope_count; do
        local scope_info=$(sqlite3 "$DB_PATH" \
            "SELECT id, total_selected, total_audited, total_pending, status, created_at
             FROM audit_scopes WHERE project_id = $project_id AND status = 'active'
             ORDER BY modified_at DESC LIMIT 1;" 2>/dev/null)
        
        if [ -z "$scope_info" ]; then
            continue
        fi
        
        IFS='|' read -r scope_id total_selected total_audited total_pending scope_status created_at <<< "$scope_info"
        
        local findings=$(sqlite3 "$DB_PATH" \
            "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0)
             FROM analysis_results ar
             WHERE ar.contract_id IN (SELECT id FROM contracts WHERE project_id = $project_id)
             AND ar.status = 'success';" 2>/dev/null || echo "0")
        
        local stats=$(sqlite3 "$DB_PATH" \
            "SELECT 
                SUM(CASE WHEN ar.status = 'success' THEN 1 ELSE 0 END) as success_count,
                SUM(CASE WHEN ar.status = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN ar.status = 'skipped' THEN 1 ELSE 0 END) as skipped_count,
                AVG(ar.analysis_duration_ms) as avg_time
             FROM analysis_results ar
             WHERE ar.contract_id IN (SELECT id FROM contracts WHERE project_id = $project_id);" 2>/dev/null)
        
        IFS='|' read -r success_count failed_count skipped_count avg_time <<< "$stats"
        success_count=${success_count:-0}
        failed_count=${failed_count:-0}
        skipped_count=${skipped_count:-0}
        avg_time=${avg_time:-0}
        
        echo -e "${MAGENTA}📦 ${BOLD}$repo_name${NC}${MAGENTA} (Scope #$scope_id)${NC}"
        echo -e "   ${DIM}Progress:${NC} ", end=""
        make_bar "$total_audited" "$total_selected"
        echo ""
        echo -e "   ${GREEN}✅ $success_count${NC} | ${RED}❌ $failed_count${NC} | ${YELLOW}⏭️ $skipped_count${NC} | ${MAGENTA}🎯 $findings findings${NC} | ${YELLOW}$total_audited/$total_selected pending: $total_pending${NC}"
        
        if [ "$avg_time" != "0" ] && [ "$avg_time" != "" ]; then
            avg_sec=$(printf "%.2f" $(echo "scale=2; $avg_time/1000" | bc))
            echo -e "   ⏱️  Avg: ${avg_sec}s"
        fi
        echo ""
    done <<< "$projects"
}

# Update recent activity
update_live_analysis() {
    echo -e "${CYAN}║${BOLD}  ⚡ LIVE ANALYSIS - Last 10 Contracts (60s window)${NC}${CYAN}                           ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    
    local recent=$(sqlite3 "$DB_PATH" \
        "SELECT c.file_path, ar.status, 
                json_extract(ar.findings, '$.total_findings') as findings, 
                printf('%.1f', ar.analysis_duration_ms/1000.0) as duration,
                ar.created_at,
                p.repo_name
         FROM analysis_results ar
         JOIN contracts c ON ar.contract_id = c.id
         JOIN projects p ON c.project_id = p.id
         WHERE ar.analysis_type='enhanced'
         AND datetime(ar.created_at) > datetime('now', '-60 seconds')
         ORDER BY ar.created_at DESC
         LIMIT 10;" 2>/dev/null)
    
    if [ -z "$recent" ]; then
        echo -e "${DIM}   (No recent activity)${NC}"
        echo ""
        return
    fi
    
    local count=1
    while IFS='|' read -r contract_path status findings duration timestamp repo_name; do
        contract_name=$(basename "$contract_path")
        
        case "$status" in
            "success")
                if [ "$findings" != "0" ] && [ "$findings" != "" ]; then
                    echo -e "   ${GREEN}✅${NC} $count. $contract_name ${MAGENTA}($findings)${NC} ${DIM}${duration}s${NC}"
                else
                    echo -e "   ${GREEN}✅${NC} $count. $contract_name ${WHITE}clean${NC} ${DIM}${duration}s${NC}"
                fi
                ;;
            "skipped")
                echo -e "   ${YELLOW}⏭️${NC} $count. $contract_name ${DIM}skipped${NC}"
                ;;
            "failed")
                echo -e "   ${RED}❌${NC} $count. $contract_name ${DIM}failed${NC}"
                ;;
        esac
        count=$((count + 1))
    done <<< "$recent"
    echo ""
}

# Update errors section
update_errors() {
    local error_count=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    
    if [ "$error_count" -gt 0 ]; then
        echo -e "${CYAN}║${BOLD}  ${RED}⚠️  ERRORS (${error_count} total)${NC}${CYAN}                                               ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
        
        sqlite3 "$DB_PATH" \
            "SELECT c.file_path, ar.error_log
             FROM analysis_results ar
             JOIN contracts c ON ar.contract_id = c.id
             WHERE ar.status='failed'
             ORDER BY ar.created_at DESC
             LIMIT 3;" 2>/dev/null | nl -w2 -s'. ' | while read num line; do
            
            IFS='|' read -r contract_path error <<< "$line"
            contract_name=$(basename "$contract_path")
            
            echo -e "   ${RED}❌${NC} $num. $contract_name"
            if [ -n "$error" ]; then
                error_short="${error:0:70}"
                echo -e "      ${YELLOW}→ ${error_short}...${NC}"
            fi
        done
        echo ""
    fi
}

# Update summary
update_summary() {
    local active_scopes=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='active';")
    local completed_scopes=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='completed';")
    local projects=$(get_db_stat "SELECT COUNT(DISTINCT id) FROM projects;")
    
    echo -e "${CYAN}║${BOLD}  📋 SUMMARY${NC}${CYAN}                                                               ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "   Active Scopes: ${BOLD}$active_scopes${NC} | Completed: ${BOLD}$completed_scopes${NC} | Projects: ${BOLD}$projects${NC}"
    echo ""
}

# Static footer
print_footer() {
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${DIM}Press Ctrl+C to exit | DB: $DB_PATH${NC}"
}

# Initial full draw
initial_draw() {
    clear
    print_header
    update_header_time
    echo ""
    update_global_stats
    update_live_projects
    update_live_analysis
    update_errors
    update_summary
    print_footer
}

# Smooth update (just refresh data sections)
smooth_update() {
    # Move cursor to line 3 (after header)
    printf '\033[3;1H'
    update_header_time
    printf '\033[6;1H'
    update_global_stats
    printf '\033[12;1H'
    update_live_projects
    printf '\033[25;1H'
    update_live_analysis
    printf '\033[37;1H'
    update_errors
    printf '\033[42;1H'
    update_summary
}

# Main monitoring loop
check_db

echo -ne "$HIDE_CURSOR"

initial_draw

while $RUNNING; do
    sleep "$REFRESH_INTERVAL"
    smooth_update
done

echo -ne "$SHOW_CURSOR"
