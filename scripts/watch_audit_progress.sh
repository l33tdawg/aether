#!/bin/bash

# AETHER AUDIT MONITOR v2 - Advanced Real-Time Monitoring System
# Polls database for live activity, tracks scopes, findings, and performance
# Usage: ./watch_audit_progress.sh [refresh_interval]

DB_PATH="$HOME/.aether/aether_github_audit.db"
REFRESH_INTERVAL=${1:-1}
RUNNING=true
LAST_CHECK=0
LAST_COUNT=0

# Color codes
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

# Trap Ctrl+C to exit gracefully
trap "RUNNING=false; clear; echo -e '${GREEN}Monitor stopped${NC}'; exit 0" SIGINT

# Check if database exists
check_db() {
    if [ ! -f "$DB_PATH" ]; then
        echo -e "${RED}❌ Database not found at $DB_PATH${NC}"
        exit 1
    fi
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

# Get database stats with caching
get_db_stat() {
    local query="$1"
    sqlite3 "$DB_PATH" "$query" 2>/dev/null || echo "0"
}

# Show main header with timestamp and system info
show_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  🔍 AETHER AUDIT MONITOR - Advanced Real-Time Multi-Project Auditing Dashboard${NC}${CYAN}   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local timestamp=$(date '+%A, %B %d, %Y | %H:%M:%S')
    local uptime=$(uptime | awk -F'up' '{print $2}' | cut -d',' -f1)
    echo -e "${WHITE}${timestamp}${NC} | Refresh: ${BOLD}${REFRESH_INTERVAL}s${NC} | ${DIM}Uptime: $(echo $uptime | xargs)${NC}"
    echo ""
}

# Show LIVE project monitoring with scope details
show_live_projects() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  📊 ACTIVE AUDITS - Live Monitoring${NC}${CYAN}                                          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Get all projects with active scopes
    local projects=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT p.id, p.repo_name, p.url, COUNT(DISTINCT s.id) as scope_count
         FROM projects p
         LEFT JOIN audit_scopes s ON p.id = s.project_id AND s.status = 'active'
         WHERE EXISTS (SELECT 1 FROM audit_scopes WHERE project_id = p.id)
         GROUP BY p.id
         ORDER BY p.id DESC;" 2>/dev/null)
    
    if [ -z "$projects" ]; then
        echo -e "${YELLOW}ℹ️  No audit projects found. Start an audit to see live monitoring.${NC}"
        echo ""
        return 1
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
        
        # Get findings for this scope
        local findings=$(sqlite3 "$DB_PATH" \
            "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0)
             FROM analysis_results ar
             WHERE ar.contract_id IN (SELECT id FROM contracts WHERE project_id = $project_id)
             AND ar.status = 'success';" 2>/dev/null || echo "0")
        
        # Get contract statistics
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
        
        # Display project
        echo -e "${MAGENTA}📦 ${BOLD}$repo_name${NC}${MAGENTA} (Scope #$scope_id)${NC}"
        echo -e "   ${DIM}URL: $url${NC}"
        echo -e "   ${DIM}Created: $created_at${NC}"
        echo ""
        
        # Scope progress with detailed bar
        echo -e "   ${BLUE}Scope Progress:${NC}"
        echo -n "   "
        make_bar "$total_audited" "$total_selected"
        echo ""
        echo ""
        
        # Detailed statistics
        echo -e "   ${BLUE}Analysis Status:${NC}"
        echo -e "      ${GREEN}✅ Successful: $success_count${NC} | ${RED}❌ Failed: $failed_count${NC} | ${YELLOW}⏭️ Skipped: $skipped_count${NC}"
        
        # Performance
        if [ "$avg_time" != "0" ] && [ "$avg_time" != "" ]; then
            avg_sec=$(printf "%.2f" $(echo "scale=2; $avg_time/1000" | bc))
            echo -e "      ⏱️  Avg Time: ${avg_sec}s"
        fi
        
        # Findings
        echo -e "   ${CYAN}🎯 Total Findings: $findings${NC}"
        echo -e "   ${YELLOW}Progress: ${BOLD}$total_audited/$total_selected${NC}${YELLOW} audited | ${BOLD}$total_pending${NC}${YELLOW} pending${NC}"
        echo ""
        
    done <<< "$projects"
    
    return 0
}

# Show LIVE contract analysis being performed
show_live_analysis() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  ⚡ LIVE ANALYSIS - Recently Updated Contracts${NC}${CYAN}                               ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Get contracts updated in last 60 seconds
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
         LIMIT 15;" 2>/dev/null)
    
    if [ -z "$recent" ]; then
        echo -e "${DIM}   (No recent activity in the last minute)${NC}"
        echo ""
        return
    fi
    
    local count=1
    while IFS='|' read -r contract_path status findings duration timestamp repo_name; do
        contract_name=$(basename "$contract_path")
        
        case "$status" in
            "success")
                if [ "$findings" != "0" ] && [ "$findings" != "" ]; then
                    echo -e "   ${GREEN}✅${NC} $count. ${BOLD}$contract_name${NC} from $repo_name"
                    echo -e "      ${MAGENTA}→ $findings findings${NC} ${DIM}(${duration}s) @ $timestamp${NC}"
                else
                    echo -e "   ${GREEN}✅${NC} $count. ${BOLD}$contract_name${NC} from $repo_name"
                    echo -e "      ${WHITE}→ clean${NC} ${DIM}(${duration}s) @ $timestamp${NC}"
                fi
                ;;
            "skipped")
                echo -e "   ${YELLOW}⏭️${NC} $count. ${BOLD}$contract_name${NC} from $repo_name ${DIM}(skipped)${NC}"
                ;;
            "failed")
                echo -e "   ${RED}❌${NC} $count. ${BOLD}$contract_name${NC} from $repo_name ${DIM}(failed)${NC}"
                ;;
            "cached")
                echo -e "   ${CYAN}⚡${NC} $count. ${BOLD}$contract_name${NC} from $repo_name ${DIM}(cached)${NC}"
                ;;
        esac
        
        count=$((count + 1))
    done <<< "$recent"
    
    echo ""
}

# Show GLOBAL statistics across all audits
show_global_stats() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  📈 GLOBAL STATISTICS - All Projects Combined${NC}${CYAN}                                 ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local successful=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='success';")
    local failed=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    local skipped=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='skipped';")
    local cached=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='cached';")
    local total=$((successful + failed + skipped + cached))
    
    local findings=$(get_db_stat "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0) FROM analysis_results WHERE status='success';")
    
    echo -e "   ${GREEN}✅ Successful: $successful${NC} | ${RED}❌ Failed: $failed${NC} | ${YELLOW}⏭️  Skipped: $skipped${NC} | ${CYAN}⚡ Cached: $cached${NC}"
    echo -e "   ${WHITE}📈 Total Contracts: $total${NC} | ${MAGENTA}🎯 Total Findings: $findings${NC}"
    echo ""
}

# Show ERRORS and FAILURES with details
show_errors() {
    local error_count=$(get_db_stat "SELECT COUNT(*) FROM analysis_results WHERE status='failed';")
    
    if [ "$error_count" -gt 0 ]; then
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${BOLD}  ${RED}⚠️  ERRORS & FAILURES (${error_count} total)${NC}${CYAN}                                           ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
        
        sqlite3 "$DB_PATH" \
            "SELECT c.file_path, ar.error_log, ar.created_at, p.repo_name
             FROM analysis_results ar
             JOIN contracts c ON ar.contract_id = c.id
             JOIN projects p ON c.project_id = p.id
             WHERE ar.status='failed'
             ORDER BY ar.created_at DESC
             LIMIT 8;" 2>/dev/null | nl -w2 -s'. ' | while read num line; do
            
            IFS='|' read -r contract_path error timestamp repo_name <<< "$line"
            contract_name=$(basename "$contract_path")
            
            echo -e "   ${RED}❌${NC} $num. ${BOLD}$contract_name${NC} from $repo_name"
            if [ -n "$error" ]; then
                error_short="${error:0:75}"
                echo -e "      ${YELLOW}→ ${error_short}...${NC}"
            fi
            echo -e "      ${DIM}@ $timestamp${NC}"
        done
        echo ""
    fi
}

# Show PERFORMANCE metrics
show_performance() {
    local stats=$(sqlite3 "$DB_PATH" \
        "SELECT 
            COALESCE(AVG(analysis_duration_ms), 0) as avg_time,
            COALESCE(MIN(analysis_duration_ms), 0) as min_time,
            COALESCE(MAX(analysis_duration_ms), 0) as max_time,
            COUNT(*) as total_analyzed
         FROM analysis_results 
         WHERE status='success';" 2>/dev/null)
    
    IFS='|' read -r avg_time min_time max_time total_analyzed <<< "$stats"
    
    if [ "$total_analyzed" -gt 0 ]; then
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${BOLD}  ⏱️  PERFORMANCE METRICS${NC}${CYAN}                                                        ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
        
        avg_sec=$(printf "%.2f" $(echo "scale=2; $avg_time/1000" | bc))
        min_sec=$(printf "%.2f" $(echo "scale=2; $min_time/1000" | bc))
        max_sec=$(printf "%.2f" $(echo "scale=2; $max_time/1000" | bc))
        
        echo -e "   Average Time: ${BOLD}${avg_sec}s${NC} | Minimum: ${GREEN}${min_sec}s${NC} | Maximum: ${YELLOW}${max_sec}s${NC} | Total Analyzed: ${BOLD}$total_analyzed${NC}"
        echo ""
    fi
}

# Show overall audit summary
show_summary() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  📋 AUDIT SUMMARY${NC}${CYAN}                                                               ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local active_scopes=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='active';")
    local completed_scopes=$(get_db_stat "SELECT COUNT(*) FROM audit_scopes WHERE status='completed';")
    local projects=$(get_db_stat "SELECT COUNT(DISTINCT id) FROM projects;")
    
    echo -e "   Active Scopes: ${BOLD}$active_scopes${NC} | Completed Scopes: ${BOLD}$completed_scopes${NC} | Total Projects: ${BOLD}$projects${NC}"
    echo ""
}

# Footer with controls
show_footer() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  ${BOLD}Press Ctrl+C to exit${NC}${CYAN} | Polling Interval: ${BOLD}${REFRESH_INTERVAL}s${NC}${CYAN} | DB: ${BOLD}$DB_PATH${NC}${CYAN}   ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Main monitoring loop
check_db

while $RUNNING; do
    show_header
    show_global_stats
    
    if ! show_live_projects; then
        echo -e "${YELLOW}No active audits running${NC}"
        echo ""
    fi
    
    show_live_analysis
    show_errors
    show_performance
    show_summary
    show_footer
    
    sleep "$REFRESH_INTERVAL"
done
