# Changes in this version (copy and guidance only)
Added: src/components/Guidance.tsx, src/styles/additions.css (imported last in main.tsx).
Welcome: "What you get" and "Three outcomes" sections, FAQ 4 -> 8 questions, second closing link.
Scanner/Scan: what happens, what you get, accepted input. Scanner/Result (empty): verdict key.
Hunter/Scan: what it looks for, how a run works. History: about saved scans.
Extension: why check first, what to do until it ships. Learn: signals table, limits, what to do with a verdict.
Results: headline stat strip, cleaner grid (fixes overflow), how to read the numbers.
Fixes: /learn and /research phone overflow. Unchanged: tokens.css, colours, fonts, motion, routes, backend.
Checks: typecheck clean, 15/15 tests, build ok, 32 route loads with 0 overflow and 0 console errors, 18/18 clicks pass.

# Review fixes on the final build
Red Team Batch: removed 12 per-sample rows that were not in results.json (outcomes and descriptions were invented); counts only now.
Red Team Techniques: removed an unverified rule-name claim; fixed phone overflow.
Research Lab: Results and Models no longer both highlight in the sidebar (NavLink end); reworded model-review notice to claims we can support.
Badges stay on one line in tables and the file tree. Duplicate sentence removed.
