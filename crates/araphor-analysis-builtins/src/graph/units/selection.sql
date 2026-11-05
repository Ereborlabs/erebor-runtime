SELECT source.record, source.window_ns, source.restricted
FROM {image}__graph_roots source {scope}
ORDER BY source.record
