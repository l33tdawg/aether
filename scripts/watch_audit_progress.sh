#!/bin/bash

# AETHER AUDIT MONITOR - top-like real-time monitoring for all active audits
# Usage: ./watch_audit_progress.sh [refresh_interval]
# Shows all projects, their scopes, progress, and real-time statistics

DB_PATH="$HOME/.aether/aether_github_audit.db"
REFRESH_INTERVAL=${1:-2}  # Refresh every N seconds (default: 2)
RUNNING=true

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Trap Ctrl+C to exit gracefully
trap "RUNNING=false; clear; echo 'Monitor stopped'; exit 0" SIGINT

# Get terminal width for dynamic formatting
get_term_width() {
    if command -v tput &> /dev/null; then
        tput cols
    else
        echo 120
    fi
}

# Print centered text
print_centered() {
    local text="$1"
    local width=$(get_term_width)
    local padding=$(( (width - ${#text}) / 2 ))
    printf "%${padding}s%s\n" "" "$text"
}

# Create progress bar
make_progress_bar() {
    local completed=$1
    local total=$2
    local width=$3
    
    if [ $total -eq 0 ]; then
        printf "[%-${width}s] 0%%\n" ""
        return
    fi
    
    local percent=$((completed * 100 / total))
    local filled=$((completed * width / total))
    local empty=$((width - filled))
    
    local bar="["
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    bar+="]"
    
    printf "%s %3d%%\n" "$bar" "$percent"
}

# Header
show_header() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  🔍 AETHER AUDIT MONITOR - top-like Real-Time Activity Monitor${NC}${CYAN}        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # System time
    echo -e "${WHITE}$(date '+%A, %B %d, %Y | %H:%M:%S')${NC}"
    echo ""
}

# Get all projects with active scopes
get_active_projects() {
    sqlite3 "$DB_PATH" \
        "SELECT DISTINCT p.id, p.url, p.repo_name 
         FROM projects p 
         WHERE EXISTS (
             SELECT 1 FROM audit_scopes WHERE project_id = p.id AND status = 'active'
         )
         ORDER BY p.id DESC;" 2>/dev/null
}

# Show audit scopes for a project
show_project_audits() {
    local project_id=$1
    local repo_name=$2
    local repo_url=$3
    
    echo -e "${MAGENTA}📦 PROJECT: ${BOLD}$repo_name${NC}${MAGENTA} (ID: $project_id)${NC}"
    echo -e "${MAGENTA}   URL: $repo_url${NC}"
    echo ""
    
    # Get scopes for this project
    local scopes=$(sqlite3 "$DB_PATH" \
        "SELECT id, total_selected, total_audited, total_pending, created_at 
         FROM audit_scopes 
         WHERE project_id = $project_id AND status = 'active'
         ORDER BY created_at DESC LIMIT 5;" 2>/dev/null)
    
    if [ -z "$scopes" ]; then
        echo -e "${YELLOW}   ⚠️  No active scopes${NC}"
        echo ""
        return
    fi
    
    while IFS='|' read -r scope_id total_selected total_audited total_pending created_at; do
        echo -e "${BLUE}   📋 Scope #$scope_id${NC} (Created: $created_at)"
        
        # Progress bar
        printf "      Progress: "
        make_progress_bar "$total_audited" "$total_selected" 30
        
        # Stats
        echo -e "      ${GREEN}✅ Audited: $total_audited${NC} | ${YELLOW}⏳ Pending: $total_pending${NC} | ${WHITE}Total: $total_selected${NC}"
        
        # Findings for this scope
        local findings=$(sqlite3 "$DB_PATH" \
            "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0)
             FROM analysis_results ar
             WHERE ar.contract_id IN (
                 SELECT id FROM contracts WHERE project_id = $project_id
             )
             AND ar.status = 'success';" 2>/dev/null || echo "0")
        
        echo -e "      ${CYAN}🎯 Total Findings: $findings${NC}"
        echo ""
    done <<< "$scopes"
}

# Show global analysis statistics
show_global_stats() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  📊 GLOBAL ANALYSIS STATISTICS${NC}${CYAN}                                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local successful=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM analysis_results WHERE status='success';" 2>/dev/null || echo "0")
    
    local failed=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM analysis_results WHERE status='failed';" 2>/dev/null || echo "0")
    
    local skipped=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM analysis_results WHERE status='skipped';" 2>/dev/null || echo "0")
    
    local cached=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM analysis_results WHERE status='cached';" 2>/dev/null || echo "0")
    
    local total=$((successful + failed + skipped + cached))
    
    local total_findings=$(sqlite3 "$DB_PATH" \
        "SELECT COALESCE(SUM(json_extract(findings, '$.total_findings')), 0) 
         FROM analysis_results WHERE status='success';" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}  ✅ Successful: $successful${NC} | ${RED}❌ Failed: $failed${NC} | ${YELLOW}⏭️  Skipped: $skipped${NC} | ${CYAN}⚡ Cached: $cached${NC}"
    echo -e "${WHITE}  📈 Total Processed: $total${NC} | ${MAGENTA}🎯 Total Findings: $total_findings${NC}"
    echo ""
}

# Show recently analyzed contracts
show_recent_activity() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}  📝 RECENT ACTIVITY (Last 10 Contracts)${NC}${CYAN}                              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    sqlite3 "$DB_PATH" \
        "SELECT c.file_path, ar.status, json_extract(ar.findings, '$.total_findings') as findings, 
                printf('%.1f', ar.analysis_duration_ms/1000.0) as duration, ar.created_at
         FROM analysis_results ar
         JOIN contracts c ON ar.contract_id = c.id
         WHERE ar.analysis_type='enhanced'
         ORDER BY ar.created_at DESC
         LIMIT 10;" 2>/dev/null | nl -w2 -s'. ' | while read num line; do
        
        IFS='|' read -r contract_path status findings duration timestamp <<< "$line"
        contract_name=$(basename "$contract_path")
        
        case "$status" in
            "success")
                if [ "$findings" != "0" ] && [ "$findings" != "" ]; then
                    echo -e "  ${GREEN}✅${NC} $num. $contract_name ${MAGENTA}($findings findings)${NC} ${YELLOW}(${duration}s)${NC} @ ${CYAN}$timestamp${NC}"
                else
                    echo -e "  ${GREEN}✅${NC} $num. $contract_name ${WHITE}(clean)${NC} ${YELLOW}(${duration}s)${NC} @ ${CYAN}$timestamp${NC}"
                fi
                ;;
            "skipped")
                echo -e "  ${YELLOW}⏭️${NC} $num. $contract_name ${WHITE}(skipped)${NC} ${YELLOW}(${duration}s)${NC} @ ${CYAN}$timestamp${NC}"
                ;;
            "failed")
                echo -e "  ${RED}❌${NC} $num. $contract_name ${WHITE}(failed)${NC} ${YELLOW}(${duration}s)${NC} @ ${CYAN}$timestamp${NC}"
                ;;
            "cached")
                echo -e "  ${CYAN}⚡${NC} $num. $contract_name ${WHITE}(cached)${NC} ${YELLOW}(${duration}s)${NC} @ ${CYAN}$timestamp${NC}"
                ;;
        esac
    done
    echo ""
}

# Show error summary
show_errors() {
    local error_count=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM analysis_results WHERE status='failed';" 2>/dev/null || echo "0")
    
    if [ "$error_count" -gt 0 ]; then
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${BOLD}  ${RED}⚠️  ERRORS & FAILURES ($error_count total)${NC}${CYAN}                                   ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
        
        sqlite3 "$DB_PATH" \
            "SELECT c.file_path, ar.error_log 
             FROM analysis_results ar
             JOIN contracts c ON ar.contract_id = c.id
             WHERE ar.status='failed'
             ORDER BY ar.created_at DESC
             LIMIT 5;" 2>/dev/null | while read -r line; do
            
            IFS='|' read -r contract_path error <<< "$line"
            contract_name=$(basename "$contract_path")
            
            echo -e "  ${RED}❌${NC} $contract_name"
            if [ -n "$error" ]; then
                error_short="${error:0:70}"
                echo -e "     ${YELLOW}→ ${error_short}...${NC}"
            fi
        done
        echo ""
    fi
}

# Show performance metrics
show_performance() {
    local avg_time=$(sqlite3 "$DB_PATH" \
        "SELECT COALESCE(AVG(analysis_duration_ms), 0) 
         FROM analysis_results WHERE status='success';" 2>/dev/null || echo "0")
    
    local min_time=$(sqlite3 "$DB_PATH" \
        "SELECT COALESCE(MIN(analysis_duration_ms), 0) 
         FROM analysis_results WHERE status='success';" 2>/dev/null || echo "0")
    
    local max_time=$(sqlite3 "$DB_PATH" \
        "SELECT COALESCE(MAX(analysis_duration_ms), 0) 
         FROM analysis_results WHERE status='success';" 2>/dev/null || echo "0")
    
    if [ "$avg_time" != "0" ]; then
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${BOLD}  ⏱️  PERFORMANCE METRICS${NC}${CYAN}                                               ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
        
        printf "  Average: %.2fs | Minimum: %.2fs | Maximum: %.2fs\n" \
            $(echo "scale=2; $avg_time/1000" | bc) \
            $(echo "scale=2; $min_time/1000" | bc) \
            $(echo "scale=2; $max_time/1000" | bc)
        echo ""
    fi
}

# Footer with controls
show_footer() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  ${BOLD}Press Ctrl+C to exit${NC}${CYAN} | Refresh interval: ${BOLD}${REFRESH_INTERVAL}s${NC}${CYAN}                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Main monitoring loop
while $RUNNING; do
    show_header
    show_global_stats
    
    # Get all active projects
    local projects=$(get_active_projects)
    
    if [ -z "$projects" ]; then
        echo -e "${YELLOW}ℹ️  No active audit scopes found. Start an audit to see progress here.${NC}"
        echo ""
    else
        # Show each project's audits
        while IFS='|' read -r project_id repo_name repo_url; do
            show_project_audits "$project_id" "$repo_name" "$repo_url"
        done <<< "$projects"
    fi
    
    show_recent_activity
    show_errors
    show_performance
    show_footer
    
    # Wait for next refresh
    sleep "$REFRESH_INTERVAL"
done
