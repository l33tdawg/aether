#!/bin/bash

# Watch Rocket Pool audit progress
# Shows progress on IMPLEMENTATIONS only (excluding interfaces that are skipped)

echo "🔍 Watching Rocket Pool audit progress..."
echo "Total contracts: 145 (80 implementations + 65 interfaces)"
echo ""

while true; do
    ANALYZED=$(sqlite3 ~/.aether/aether_github_audit.db \
        "SELECT COUNT(*) FROM analysis_results \
         WHERE contract_id IN (SELECT id FROM contracts WHERE project_id=22) \
         AND analysis_type='enhanced' AND status='success';")
    
    SKIPPED=$(sqlite3 ~/.aether/aether_github_audit.db \
        "SELECT COUNT(*) FROM analysis_results \
         WHERE contract_id IN (SELECT id FROM contracts WHERE project_id=22) \
         AND analysis_type='enhanced' AND status='skipped';")
    
    TOTAL_PROCESSED=$((ANALYZED + SKIPPED))
    
    # Progress of implementations (80 total, not 145)
    IMPL_PERCENT=$((ANALYZED * 100 / 80))
    IMPL_REMAINING=$((80 - ANALYZED))
    
    # Progress bars
    IMPL_FILLED=$((ANALYZED / 2))
    IMPL_EMPTY=$((20 - IMPL_FILLED))
    IMPL_BAR="["
    for ((i=0; i<IMPL_FILLED; i++)); do IMPL_BAR+="█"; done
    for ((i=0; i<IMPL_EMPTY; i++)); do IMPL_BAR+="░"; done
    IMPL_BAR+="]"
    
    printf "\r📊 Implementations: $IMPL_BAR %3d%% (%2d/80) | Interfaces: %2d/65 ⏭️ | Total: %3d/145         " $IMPL_PERCENT $ANALYZED $SKIPPED $TOTAL_PROCESSED
    
    # Check if complete
    if [ $TOTAL_PROCESSED -eq 145 ]; then
        echo ""
        echo "✅ AUDIT COMPLETE!"
        echo "   Implementations analyzed: $ANALYZED/80"
        echo "   Interfaces skipped: $SKIPPED/65"
        echo "   Total processed: $TOTAL_PROCESSED/145"
        break
    fi
    
    sleep 5
done
