#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🧹 Cleaning comments from source files and Python scripts${NC}"
echo -e "${BLUE}Focusing on: src directories, Python scripts, excluding env files${NC}"

# Function to clean Python files
clean_python() {
    local file="$1"
    echo "Cleaning Python: $file"
    
    # Remove only obvious comment lines, preserve docstrings and important comments
    sed -i.bak '
        # Skip shebang
        1{/^#!/b}
        # Remove lines that are only comments (starting with # after optional whitespace)
        /^[[:space:]]*#[[:space:]]*$/d
        # Remove obvious comment lines but preserve TODO, FIXME, NOTE, etc.
        /^[[:space:]]*#[[:space:]]*[^TFINW]/d
    ' "$file"
    
    rm "$file.bak" 2>/dev/null || true
}

# Function to clean JavaScript/TypeScript files  
clean_js() {
    local file="$1"
    echo "Cleaning JS/TS: $file"
    
    sed -i.bak '
        # Remove lines that are only // comments
        /^[[:space:]]*\/\/[[:space:]]*$/d
        # Remove obvious // comment lines but preserve TODO, FIXME, etc.
        /^[[:space:]]*\/\/[[:space:]]*[^TFINW]/d
    ' "$file"
    
    rm "$file.bak" 2>/dev/null || true
}

# Process Python files - focus on source directories and scripts
echo "Processing Python files in source directories and scripts..."

# Backend Python files
find ./backend -name "*.py" -type f 2>/dev/null | while read -r file; do
    # Skip env files
    if [[ "$file" =~ \.env ]]; then
        echo "Skipping env file: $file"
        continue
    fi
    clean_python "$file"
done

# Scripts directories
find . -path "*/scripts/*" -name "*.py" -not -path "./saptara/*" -not -path "./node_modules/*" -type f 2>/dev/null | while read -r file; do
    clean_python "$file"
done

# Root level Python scripts (max depth 2)
find . -maxdepth 2 -name "*.py" -not -path "./saptara/*" -not -path "./node_modules/*" -not -path "./backend/*" -type f 2>/dev/null | while read -r file; do
    # Skip env files
    if [[ "$file" =~ \.env ]]; then
        echo "Skipping env file: $file"
        continue
    fi
    clean_python "$file"
done

echo "Processing JavaScript/TypeScript files in source directories..."

# Frontend src files only
find ./frontend/src -type f \( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \) 2>/dev/null | while read -r file; do
    clean_js "$file"
done

echo -e "${GREEN}✅ Comment cleaning completed!${NC}"
echo -e "${YELLOW}Note: Focused on source directories and Python scripts, excluded env files${NC}"

# Show summary
echo ""
echo "Summary:"
echo "- Processed Python files in: backend/, scripts/ directories, and root-level scripts"
echo "- Processed JS/TS files in: frontend/src/ directory"
echo "- Excluded: .env files, node_modules/, saptara/"
echo "- Removed empty comment lines and basic comments"
echo "- Preserved TODO, FIXME, NOTE, WARNING comments"
echo "- Preserved docstrings and multiline comments"
echo "- Preserved shebang lines"