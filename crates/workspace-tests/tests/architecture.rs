//! Test de arquitectura (plan 4.1): hace cumplir la tabla de dependencias permitidas
//! entre los crates del workspace. Solo cuentan las dependencias normales.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargo_metadata::{DependencyKind, MetadataCommand};

const DOMAIN_PERMITIDAS: &[&str] = &["base64", "secrecy", "sha2", "subtle", "thiserror", "zeroize"];
const APPLICATION_PERMITIDAS: &[&str] = &["domain", "tracing"];

const PROHIBIDAS_EXACTAS: &[&str] = &[
    "tokio",
    "reqwest",
    "hyper",
    "axum",
    "openidconnect",
    "serde",
    "lambda_http",
    "lambda_runtime",
];
const PROHIBIDAS_PREFIJO: &[&str] = &["aws_"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Categoria {
    Domain,
    Application,
    Adapter,
    Lambda,
    WorkspaceTests,
}

#[derive(Debug, Clone)]
struct Miembro {
    nombre: String,
    ruta_relativa: String,
    deps_directas: BTreeSet<String>,
}

type Grafo = BTreeMap<String, BTreeSet<String>>;

fn normalizar(nombre: &str) -> String {
    nombre.replace('-', "_")
}

fn clasificar(nombre: &str, ruta_relativa: &str) -> Option<Categoria> {
    let ruta = ruta_relativa.replace('\\', "/");
    if ruta.starts_with("crates/adapters/") {
        return Some(Categoria::Adapter);
    }
    match nombre {
        "domain" => Some(Categoria::Domain),
        "application" => Some(Categoria::Application),
        "lambda" => Some(Categoria::Lambda),
        "workspace-tests" => Some(Categoria::WorkspaceTests),
        _ => None,
    }
}

fn es_prohibida(nombre: &str) -> bool {
    let n = normalizar(nombre);
    PROHIBIDAS_EXACTAS.contains(&n.as_str()) || PROHIBIDAS_PREFIJO.iter().any(|p| n.starts_with(p))
}

fn alcanzables(grafo: &Grafo, inicio: &BTreeSet<String>) -> BTreeSet<String> {
    let mut vistos = BTreeSet::new();
    let mut pendientes: Vec<String> = inicio.iter().cloned().collect();
    while let Some(actual) = pendientes.pop() {
        if !vistos.insert(actual.clone()) {
            continue;
        }
        if let Some(hijos) = grafo.get(&actual) {
            pendientes.extend(hijos.iter().cloned());
        }
    }
    vistos
}

fn verificar_lista_blanca(miembro: &Miembro, permitidas: &[&str], violaciones: &mut Vec<String>) {
    for dep in &miembro.deps_directas {
        if !permitidas.contains(&dep.as_str()) {
            violaciones.push(format!(
                "`{}` depende de `{dep}`, que no esta permitido (permitidas: {})",
                miembro.nombre,
                permitidas.join(", ")
            ));
        }
    }
}

fn verificar_transitivas(miembro: &Miembro, grafo: &Grafo, violaciones: &mut Vec<String>) {
    for dep in alcanzables(grafo, &miembro.deps_directas) {
        if es_prohibida(&dep) {
            violaciones.push(format!(
                "`{}` depende (posiblemente transitivamente) de `{dep}`, prohibido en el nucleo",
                miembro.nombre
            ));
        }
    }
}

fn verificar(miembros: &[Miembro], grafo: &Grafo) -> Vec<String> {
    let mut violaciones = Vec::new();
    let nombres_adaptadores: BTreeSet<&str> = miembros
        .iter()
        .filter(|m| clasificar(&m.nombre, &m.ruta_relativa) == Some(Categoria::Adapter))
        .map(|m| m.nombre.as_str())
        .collect();

    for miembro in miembros {
        match clasificar(&miembro.nombre, &miembro.ruta_relativa) {
            None => violaciones.push(format!(
                "el crate `{}` ({}) no esta clasificado: hay que clasificarlo en `clasificar` \
                 de tests/architecture.rs y definir sus dependencias permitidas",
                miembro.nombre, miembro.ruta_relativa
            )),
            Some(Categoria::Domain) => {
                verificar_lista_blanca(miembro, DOMAIN_PERMITIDAS, &mut violaciones);
                verificar_transitivas(miembro, grafo, &mut violaciones);
            }
            Some(Categoria::Application) => {
                verificar_lista_blanca(miembro, APPLICATION_PERMITIDAS, &mut violaciones);
                verificar_transitivas(miembro, grafo, &mut violaciones);
            }
            Some(Categoria::Adapter) => {
                for dep in &miembro.deps_directas {
                    if dep == "lambda" || nombres_adaptadores.contains(dep.as_str()) {
                        violaciones.push(format!(
                            "el adaptador `{}` no puede depender de `{dep}` (otro adaptador o lambda)",
                            miembro.nombre
                        ));
                    }
                }
            }
            Some(Categoria::Lambda | Categoria::WorkspaceTests) => {}
        }
    }
    violaciones
}

fn cargar_workspace() -> Result<(Vec<Miembro>, Grafo), Box<dyn std::error::Error>> {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = MetadataCommand::new()
        .manifest_path(raiz.join("Cargo.toml"))
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata sin grafo resolve")?;

    let nombre_por_id: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|p| (p.id.clone(), p.name.to_string()))
        .collect();

    let mut grafo = Grafo::new();
    for nodo in &resolve.nodes {
        let Some(nombre) = nombre_por_id.get(&nodo.id) else {
            continue;
        };
        let hijos = grafo.entry(nombre.clone()).or_default();
        for dep in &nodo.deps {
            let normal = dep.dep_kinds.iter().any(|k| k.kind == DependencyKind::Normal);
            if let (true, Some(hijo)) = (normal, nombre_por_id.get(&dep.pkg)) {
                hijos.insert(hijo.clone());
            }
        }
    }

    let raiz_ws = metadata.workspace_root.as_std_path();
    let mut miembros = Vec::new();
    for paquete in metadata.workspace_packages() {
        let dir = paquete
            .manifest_path
            .as_std_path()
            .parent()
            .ok_or("manifest sin directorio")?;
        let ruta_relativa = dir.strip_prefix(raiz_ws)?.to_string_lossy().into_owned();
        let deps_directas = paquete
            .dependencies
            .iter()
            .filter(|d| d.kind == DependencyKind::Normal)
            .map(|d| d.name.clone())
            .collect();
        miembros.push(Miembro {
            nombre: paquete.name.to_string(),
            ruta_relativa,
            deps_directas,
        });
    }
    Ok((miembros, grafo))
}

#[test]
fn el_workspace_respeta_los_limites_de_arquitectura() {
    let (miembros, grafo) = cargar_workspace().expect("no se pudo leer el workspace");
    assert!(
        miembros.iter().any(|m| m.nombre == "domain"),
        "el workspace deberia incluir `domain`"
    );
    let violaciones = verificar(&miembros, &grafo);
    assert!(
        violaciones.is_empty(),
        "violaciones de arquitectura:\n- {}",
        violaciones.join("\n- ")
    );
}

#[cfg(test)]
mod logica {
    use super::*;

    fn miembro(nombre: &str, ruta: &str, deps: &[&str]) -> Miembro {
        Miembro {
            nombre: nombre.to_owned(),
            ruta_relativa: ruta.to_owned(),
            deps_directas: deps.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    fn grafo(aristas: &[(&str, &[&str])]) -> Grafo {
        aristas
            .iter()
            .map(|(n, hs)| ((*n).to_owned(), hs.iter().map(|h| (*h).to_owned()).collect()))
            .collect()
    }

    #[test]
    fn configuracion_valida_no_tiene_violaciones() {
        let miembros = [
            miembro("domain", "crates/domain", &["sha2", "thiserror"]),
            miembro("application", "crates/application", &["domain", "tracing"]),
            miembro(
                "oidc-cognito",
                "crates/adapters/oidc-cognito",
                &["domain", "application", "reqwest"],
            ),
            miembro("lambda", "crates/lambda", &["oidc-cognito", "tokio"]),
            miembro("workspace-tests", "crates/workspace-tests", &[]),
        ];
        let g = grafo(&[("domain", &["sha2"]), ("sha2", &["digest"])]);
        assert!(verificar(&miembros, &g).is_empty());
    }

    #[test]
    fn domain_con_dependencia_no_listada_falla() {
        let miembros = [miembro("domain", "crates/domain", &["url"])];
        let v = verificar(&miembros, &Grafo::new());
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("`url`"));
    }

    #[test]
    fn domain_con_dependencia_transitiva_prohibida_falla() {
        let miembros = [miembro("domain", "crates/domain", &["thiserror"])];
        let g = grafo(&[("thiserror", &["serde"])]);
        let v = verificar(&miembros, &g);
        assert!(v.iter().any(|m| m.contains("`serde`")), "{v:?}");
    }

    #[test]
    fn prefijo_aws_es_prohibido_en_application() {
        let miembros = [miembro(
            "application",
            "crates/application",
            &["domain", "aws-config"],
        )];
        let g = grafo(&[("aws-config", &["aws_smithy_runtime"])]);
        let v = verificar(&miembros, &g);
        assert!(v.iter().any(|m| m.contains("`aws-config`")), "{v:?}");
        assert!(v.iter().any(|m| m.contains("`aws_smithy_runtime`")), "{v:?}");
    }

    #[test]
    fn adaptador_no_puede_depender_de_otro_adaptador_ni_de_lambda() {
        let miembros = [
            miembro("a", "crates/adapters/a", &["domain", "b", "lambda"]),
            miembro("b", "crates/adapters/b", &["application"]),
            miembro("lambda", "crates/lambda", &["a", "b"]),
        ];
        let v = verificar(&miembros, &Grafo::new());
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().any(|m| m.contains("`b`")));
        assert!(v.iter().any(|m| m.contains("`lambda`")));
    }

    #[test]
    fn crate_sin_clasificar_falla_pidiendo_clasificarlo() {
        let miembros = [miembro("nuevo", "crates/nuevo", &[])];
        let v = verificar(&miembros, &Grafo::new());
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("clasificar"));
    }

    #[test]
    fn crates_ausentes_se_omiten() {
        let miembros = [miembro("domain", "crates/domain", &["base64"])];
        assert!(verificar(&miembros, &Grafo::new()).is_empty());
    }
}
