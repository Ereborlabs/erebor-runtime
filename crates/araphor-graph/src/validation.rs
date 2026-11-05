use duckdb::{params, Connection};
use snafu::ResultExt as _;

use crate::error::{DatabaseSnafu, InvalidSnafu};
use crate::{GraphStore, Result};

impl GraphStore {
    pub fn validate(connection: &Connection) -> Result<()> {
        let invalid: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM graph_writers WHERE writer_id=0 OR graph_id=0)
             OR EXISTS(SELECT 1 FROM graph_relations relation
                LEFT JOIN graph_relations source ON source.relation_id=relation.from_relation
                LEFT JOIN graph_relations target ON target.relation_id=relation.to_relation
                WHERE relation.relation_id=0 OR relation.graph_id=0 OR relation.entity_kind NOT IN (0,1)
                    OR (relation.entity_kind=0 AND (relation.from_relation IS NOT NULL OR relation.to_relation IS NOT NULL))
                    OR (relation.entity_kind=1 AND (source.relation_id IS NULL OR target.relation_id IS NULL
                        OR source.entity_kind<>0 OR target.entity_kind<>0
                        OR source.graph_id<>relation.graph_id OR target.graph_id<>relation.graph_id)))
             OR EXISTS(SELECT 1 FROM graph_layers layer LEFT JOIN graph_writers writer USING(writer_id)
                LEFT JOIN graph_layers parent ON parent.layer_id=layer.parent_id
                WHERE layer.layer_id=0 OR layer.revision=0 OR writer.writer_id IS NULL
                    OR (layer.parent_id IS NOT NULL AND (parent.layer_id IS NULL OR parent.writer_id<>layer.writer_id OR parent.revision>=layer.revision))
                    OR layer.parent_id IS DISTINCT FROM (SELECT prior.layer_id FROM graph_layers prior
                        WHERE prior.writer_id=layer.writer_id AND prior.revision<layer.revision ORDER BY prior.revision DESC LIMIT 1))
             OR EXISTS(SELECT 1 FROM graph_members member
                LEFT JOIN graph_writers writer USING(writer_id)
                LEFT JOIN graph_writer_owners owner ON owner.writer_id=member.writer_id AND owner.owner_ref=member.owner_ref
                LEFT JOIN graph_relations relation ON relation.relation_id=member.relation_id AND relation.graph_id=writer.graph_id
                LEFT JOIN graph_entities entity ON entity.entity_ref=member.entity_ref AND entity.relation_id=member.relation_id AND entity.entity_key=member.entity_key
                LEFT JOIN graph_layers opened ON opened.writer_id=member.writer_id AND opened.revision=member.valid_from
                LEFT JOIN graph_layers closed ON closed.writer_id=member.writer_id AND closed.revision=member.valid_to
                LEFT JOIN graph_labels label ON label.label_ref=member.label_ref AND label.graph_id=writer.graph_id
                WHERE writer.writer_id IS NULL OR owner.owner_ref IS NULL OR relation.relation_id IS NULL
                    OR entity.entity_ref IS NULL OR opened.layer_id IS NULL OR member.properties_ref=0
                    OR (member.valid_to IS NOT NULL AND (closed.layer_id IS NULL OR member.valid_to<=member.valid_from))
                    OR member.entity_kind<>relation.entity_kind
                    OR (member.entity_kind=0 AND (member.from_ref IS NOT NULL OR member.to_ref IS NOT NULL OR member.label_ref IS NOT NULL))
                    OR (member.entity_kind=1 AND (member.from_ref IS NULL OR member.to_ref IS NULL OR label.label_ref IS NULL))
                    OR EXISTS(SELECT 1 FROM graph_members other WHERE other.writer_id=member.writer_id
                        AND other.owner_ref=member.owner_ref AND other.relation_id=member.relation_id AND other.entity_key=member.entity_key
                        AND other.valid_from>member.valid_from AND (member.valid_to IS NULL OR other.valid_from<member.valid_to)))",
            [], |row| row.get(0),
        ).context(DatabaseSnafu { operation: "validate Graph layers" })?;
        if invalid {
            return InvalidSnafu {
                field: "Graph stored layers",
            }
            .fail();
        }
        let mut statement = connection
            .prepare("SELECT relation_id FROM graph_relations ORDER BY relation_id")
            .context(DatabaseSnafu {
                operation: "prepare Graph property validation",
            })?;
        let relations = statement
            .query_map([], |row| row.get::<_, u64>(0))
            .context(DatabaseSnafu {
                operation: "read Graph property relations",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(DatabaseSnafu {
                operation: "decode Graph property relations",
            })?;
        for relation in relations {
            let invalid: bool = connection.query_row(&format!(
                "SELECT EXISTS(SELECT 1 FROM graph_members member LEFT JOIN graph_properties_{relation} property
                    ON property.property_ref=member.properties_ref WHERE member.relation_id=? AND property.property_ref IS NULL)"),
                params![relation], |row| row.get(0),
            ).context(DatabaseSnafu { operation: "validate Graph property references" })?;
            if invalid {
                return InvalidSnafu {
                    field: "Graph stored properties",
                }
                .fail();
            }
        }
        Ok(())
    }
}
