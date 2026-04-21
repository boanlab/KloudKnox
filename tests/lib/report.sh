#!/usr/bin/env bash
# Append-only Markdown report generator.
# State is kept in artifacts/report.md, refreshed at each report_reset.

REPORT_MD="${ART_DIR}/report.md"

report_reset() {
    mkdir -p "${ART_DIR}"
    {
        echo "# KloudKnox E2E Report"
        echo ""
        echo "Run at: $(date -Iseconds)"
        echo ""
    } >"${REPORT_MD}"
}

report_begin_case() {
    local id="$1" name="$2" count="$3"
    {
        echo ""
        echo "## ${id} — ${name}"
        echo ""
        echo "| # | pod | cmd | expect | result | reason |"
        echo "|---|-----|-----|--------|--------|--------|"
    } >>"${REPORT_MD}"
}

_report_md_escape() {
    sed -e 's/|/\\|/g' -e 's/`/\\`/g' <<<"$1"
}

report_step() {
    local id="$1" n="$2" pod="$3" cmd="$4" expect="$5" verdict="$6" reason="$7"
    local ec
    ec="$(_report_md_escape "${cmd}")"
    local er
    er="$(_report_md_escape "${reason}")"
    printf '| %s | %s | `%s` | %s | %s | %s |\n' \
        "${n}" "${pod}" "${ec}" "${expect}" "${verdict}" "${er}" >>"${REPORT_MD}"
}

report_end_case() {
    local id="$1" pass="$2" fail="$3" total="$4"
    {
        echo ""
        if [[ "${fail}" -eq 0 ]]; then
            echo "**${id} result: PASS (${pass}/${total})**"
        else
            echo "**${id} result: FAIL (${pass}/${total} passed, ${fail} failed)**"
        fi
    } >>"${REPORT_MD}"
}

report_summary() {
    local pass="$1" fail="$2"
    {
        echo ""
        echo "## Summary"
        echo ""
        echo "- cases passed: ${pass}"
        echo "- cases failed: ${fail}"
    } >>"${REPORT_MD}"

    echo ""
    echo "report: ${REPORT_MD}"
    echo "summary: ${pass} PASS, ${fail} FAIL"
}
