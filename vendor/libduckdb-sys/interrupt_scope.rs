use std::{fs, path::Path};

pub fn patch(root: &Path) {
    for (name, before, after, count) in [
        (
            "src/include/duckdb/main/client_context.hpp",
            "\tatomic<bool> interrupted;",
            "\tatomic<bool> interrupted;\n\tatomic<uint8_t> interrupt_scope {0};",
            1,
        ),
        (
            "src/main/client_context.cpp",
            "\tinterrupted = false;",
            "\tClearInterrupt();",
            4,
        ),
        (
            "src/main/client_context.cpp",
            "void ClientContext::ClearInterrupt() {\n\tClearInterrupt();\n}",
            "void ClientContext::ClearInterrupt() {\n\tinterrupted = false;\n\tif (interrupt_scope == 2) {\n\t\tinterrupted = true;\n\t}\n}",
            1,
        ),
        (
            "src/main/client_context.cpp",
            "\tCleanupInternal(lock);\n\tClearInterrupt();",
            "\tCleanupInternal(lock);\n\tClearInterrupt();\n\tif (interrupt_scope == 2) {\n\t\tthrow InterruptException();\n\t}",
            1,
        ),
        (
            "src/verification/prepared_statement_verifier.cpp",
            "context.interrupted = false;",
            "context.ClearInterrupt();",
            1,
        ),
        (
            "src/verification/statement_verifier.cpp",
            "context.interrupted = false;",
            "context.ClearInterrupt();",
            2,
        ),
        (
            "src/include/duckdb.h",
            "DUCKDB_C_API void duckdb_interrupt(duckdb_connection connection);",
            "DUCKDB_C_API void duckdb_interrupt(duckdb_connection connection);\nDUCKDB_C_API duckdb_state duckdb_begin_interrupt_scope(duckdb_connection connection);\nDUCKDB_C_API void duckdb_end_interrupt_scope(duckdb_connection connection);",
            1,
        ),
        (
            "src/main/capi/duckdb-c.cpp",
            "\tconn->Interrupt();\n}",
            "\tuint8_t active = 1;\n\tconn->context->interrupt_scope.compare_exchange_strong(active, 2);\n\tconn->Interrupt();\n}\n\nduckdb_state duckdb_begin_interrupt_scope(duckdb_connection connection) {\n\tif (!connection) {\n\t\treturn DuckDBError;\n\t}\n\tauto &state = reinterpret_cast<Connection *>(connection)->context->interrupt_scope;\n\tuint8_t inactive = 0;\n\treturn state.compare_exchange_strong(inactive, 1) ? DuckDBSuccess : DuckDBError;\n}\n\nvoid duckdb_end_interrupt_scope(duckdb_connection connection) {\n\tif (connection) {\n\t\treinterpret_cast<Connection *>(connection)->context->interrupt_scope = 0;\n\t}\n}",
            1,
        ),
    ] {
        let path = root.join(name);
        let source = fs::read_to_string(&path).expect("read pinned DuckDB source");
        assert_eq!(
            source.matches(before).count(),
            count,
            "DuckDB interrupt patch: {name}"
        );
        fs::write(path, source.replace(before, after)).expect("patch pinned DuckDB source");
    }
}
