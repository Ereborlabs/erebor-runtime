SELECT * FROM "HF-PROC-001"."1".detect('subjects')
UNION ALL
SELECT * FROM "HF-DW-001"."1".detect('subjects')
UNION ALL
SELECT * FROM "HF-XNODE-001"."1".detect('subjects')
