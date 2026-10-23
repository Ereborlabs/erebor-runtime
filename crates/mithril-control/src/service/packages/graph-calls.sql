SELECT * FROM "HF-PROC-001"."1".detect('subjects',
    records => (SELECT * FROM records), facts => (SELECT * FROM facts),
    manifest => (SELECT * FROM manifest))
UNION ALL
SELECT * FROM "HF-DW-001"."1".detect('subjects',
    records => (SELECT * FROM records), facts => (SELECT * FROM facts),
    manifest => (SELECT * FROM manifest))
UNION ALL
SELECT * FROM "HF-XNODE-001"."1".detect('subjects',
    records => (SELECT * FROM records), facts => (SELECT * FROM facts),
    manifest => (SELECT * FROM manifest))
