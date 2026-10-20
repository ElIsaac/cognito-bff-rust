//! Tests de contrato de los almacenes: la misma bateria contra `in-memory` (referencia) y
//! contra `session-dynamodb` sobre `DynamoDB` Local (`DYNAMODB_ENDPOINT_URL`). Demuestran
//! que ambos tienen la semantica que `application` supone.

mod dynamo;
mod inmem;
mod suite;

/// Genera, para cada funcion de la bateria, un test contra cada implementacion.
macro_rules! contrato {
    ($($caso:ident),* $(,)?) => {
        mod en_memoria {
            use crate::{inmem::Harness, suite};
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $caso() {
                    suite::$caso(&Harness::new()).await;
                }
            )*
        }

        mod en_dynamodb {
            use crate::{dynamo::Harness, suite};
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn $caso() {
                    suite::$caso(&Harness::new().await).await;
                }
            )*
        }
    };
}

contrato!(
    get_de_inexistente_es_none,
    create_duplicado_es_permanente_y_no_pisa,
    roundtrip_completo_de_sesion,
    roundtrip_con_usuario_minimo,
    update_con_version_correcta,
    update_con_version_incorrecta_es_conflicto,
    update_de_inexistente_es_conflicto,
    update_borra_refresh_lock_until,
    ttl_de_sesion_persistido_y_actualizado,
    lease_libre,
    lease_vigente_es_conflicto,
    lease_vencido_se_toma,
    lease_en_el_limite_exacto_es_conflicto,
    lease_con_version_distinta_es_conflicto,
    lease_de_inexistente_es_conflicto,
    lease_no_crea_la_sesion,
    delete_es_idempotente,
    pending_roundtrip_y_ttl,
    pending_se_consume_una_sola_vez,
    pending_duplicado_es_permanente,
    ticket_roundtrip_y_ttl,
    ticket_se_consume_una_sola_vez,
    consume_concurrente_devuelve_una_sola_vez,
    namespaces_separados_por_prefijo,
    carrera_de_50_leases_un_solo_ganador,
);
