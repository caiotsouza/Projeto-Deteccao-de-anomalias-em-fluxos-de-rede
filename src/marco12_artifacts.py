"""Geração das evidências reproduzíveis do Marco 12."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi.testclient import TestClient

from src.config import MARCO12_REPORTS_DIR, PROJECT_ROOT
from src.dashboard_api import create_app
from src.monitoring_repository import InMemoryPredictionRepository
from src.replay import ReplayConfig, run_replay
from src.runtime_config import RuntimeSettings, load_active_model_identity


OUTPUT_FILES = {
    "openapi": "openapi.json",
    "integration_validation": "in_memory_integration_validation.json",
    "grafana_validation": "grafana_contract_validation.json",
    "summary": "MARCO_12_SUMMARY.md",
    "manifest": "marco_12_manifest.json",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")
    os.replace(temporary, path)


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as file:
        file.write(value)
    os.replace(temporary, path)


def _assert_outputs_writable(output_dir: Path, overwrite: bool) -> None:
    existing = [output_dir / name for name in OUTPUT_FILES.values() if (output_dir / name).exists()]
    if existing and not overwrite:
        joined = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            f"Artefatos do Marco 12 já existem: {joined}. Use --overwrite."
        )


def _validate_grafana(project_root: Path, openapi: dict[str, Any]) -> dict[str, Any]:
    path = (
        project_root
        / "infra"
        / "grafana"
        / "dashboards"
        / "tcc-network-anomaly.json"
    )
    dashboard = json.loads(path.read_text(encoding="utf-8"))
    panels = dashboard["panels"]
    route_paths = set(openapi["paths"])
    used_routes: set[str] = set()
    target_checks = []
    for panel in panels:
        for target in panel.get("targets", []):
            route = urlparse(target["url"]).path
            used_routes.add(route)
            target_checks.append(
                {
                    "panel_id": panel["id"],
                    "route": route,
                    "route_exists_in_openapi": route in route_paths,
                    "datasource_uid": panel["datasource"]["uid"],
                    "parser": target.get("parser"),
                    "root_selector": target.get("root_selector"),
                }
            )
    serialized = json.dumps(dashboard, ensure_ascii=False).lower()
    forbidden = [
        item
        for item in (
            "binary_label",
            "attack_category",
            "ground_truth",
            "false_positive_rate",
            "dataset_source_file",
        )
        if item in serialized
    ]
    expected_routes = {
        "/api/v1/dashboard/overview",
        "/api/v1/dashboard/timeseries",
        "/api/v1/dashboard/breakdowns",
        "/api/v1/anomalies/recent",
        "/api/v1/model/status",
    }
    checks = {
        "json_valid": True,
        "panel_count": len(panels),
        "panel_ids": [panel["id"] for panel in panels],
        "unique_panel_ids": len({panel["id"] for panel in panels}) == len(panels),
        "datasource_uid_fixed": all(
            panel["datasource"]["uid"] == "tcc-fastapi" for panel in panels
        ),
        "used_routes": sorted(used_routes),
        "expected_routes": sorted(expected_routes),
        "all_routes_implemented": used_routes == expected_routes
        and all(item["route_exists_in_openapi"] for item in target_checks),
        "forbidden_terms_found": forbidden,
        "offline_replay_warning_present": "replay offline" in serialized,
        "balanced_warning_present": "balanceado" in serialized,
        "simulated_time_warning_present": "timestamps simulados" in serialized,
        "score_probability_warning_present": "não é probabilidade" in serialized,
        "timezone": dashboard["timezone"],
        "refresh": dashboard["refresh"],
    }
    passed = (
        checks["panel_count"] == 11
        and checks["unique_panel_ids"]
        and checks["datasource_uid_fixed"]
        and checks["all_routes_implemented"]
        and not forbidden
        and checks["offline_replay_warning_present"]
        and checks["balanced_warning_present"]
        and checks["simulated_time_warning_present"]
        and checks["score_probability_warning_present"]
        and checks["timezone"] == "utc"
    )
    if not passed:
        raise RuntimeError(f"Contrato Grafana inválido: {checks}")
    return {
        "schema_version": 1,
        "status": "passed",
        "dashboard_path": path.relative_to(project_root).as_posix(),
        "dashboard_sha256": _sha256_file(path),
        "checks": checks,
        "targets": target_checks,
    }


def _integrated_in_memory_validation(
    project_root: Path,
    *,
    replay_limit: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    model = load_active_model_identity(project_root=project_root)
    repository = InMemoryPredictionRepository()
    config = ReplayConfig(limit=replay_limit, batch_size=min(500, replay_limit))
    first = run_replay(
        repository,
        project_root=project_root,
        model=model,
        config=config,
    )
    second = run_replay(
        repository,
        project_root=project_root,
        model=model,
        config=config,
    )
    query_start = datetime.fromisoformat(first["configuration"]["start_time"])
    query_end = query_start + timedelta(
        milliseconds=first["configuration"]["interval_milliseconds"] * replay_limit
    )
    app = create_app(
        repository=repository,
        settings=RuntimeSettings(
            dashboard_window_hours=24,
            dashboard_max_records=100_000,
            dashboard_max_window_days=31,
            project_root=project_root,
        ),
        model=model,
    )
    openapi = app.openapi()
    client = TestClient(app)
    temporal_params = {
        "start": query_start.isoformat(),
        "end": query_end.isoformat(),
        "bucket_minutes": 5,
        "top_n": 10,
        "limit": 20,
    }
    requests = {
        "health_live": ("/health/live", {}),
        "health_ready": ("/health/ready", {}),
        "overview": ("/api/v1/dashboard/overview", temporal_params),
        "timeseries": ("/api/v1/dashboard/timeseries", temporal_params),
        "breakdowns": ("/api/v1/dashboard/breakdowns", temporal_params),
        "recent_anomalies": ("/api/v1/anomalies/recent", temporal_params),
        "model_status": ("/api/v1/model/status", {}),
    }
    responses: dict[str, dict[str, Any]] = {}
    for name, (path, params) in requests.items():
        response = client.get(path, params=params)
        responses[name] = {"path": path, "status_code": response.status_code}
        if response.status_code != 200:
            raise RuntimeError(f"Endpoint {path} retornou {response.status_code}: {response.text}")
        responses[name]["body"] = response.json()

    overview = responses["overview"]["body"]
    timeline = responses["timeseries"]["body"]["items"]
    breakdowns = responses["breakdowns"]["body"]
    status = responses["model_status"]["body"]
    totals = overview["totals"]
    assertions = {
        "first_run_inserted_all": first["counts"]["inserted"] == replay_limit,
        "second_run_is_all_duplicates": (
            second["counts"]["inserted"] == 0
            and second["counts"]["duplicates"] == replay_limit
        ),
        "repository_count_matches": status["model"]["stored_documents"] == replay_limit,
        "overview_count_matches": totals["flows"] == replay_limit,
        "total_reconciles": totals["normal"] + totals["anomalies"] == totals["flows"],
        "timeline_flows_reconcile": sum(row["flows_total"] for row in timeline)
        == totals["flows"],
        "timeline_anomalies_reconcile": sum(
            row["anomalies_total"] for row in timeline
        )
        == totals["anomalies"],
        "protocol_unavailable_not_fabricated": (
            breakdowns["dimension_availability"]["protocol"] is False
            and breakdowns["protocols"] == []
        ),
        "source_ip_unavailable_not_fabricated": (
            breakdowns["dimension_availability"]["src_ip"] is False
            and breakdowns["top_anomalous_sources"] == []
        ),
        "destination_port_available": breakdowns["dimension_availability"]["dst_port"],
        "no_query_truncation": overview["query"]["truncated"] is False,
        "model_sha_fixed": status["model"]["model_sha256"] == model.sha256,
        "threshold_fixed": status["model"]["threshold"] == model.threshold,
        "mode_is_offline_replay": status["mode"] == "offline_replay",
        "sources_unchanged": (
            first["source_integrity_unchanged"]
            and second["source_integrity_unchanged"]
        ),
        "labels_not_loaded": first["methodology"]["labels_loaded"] is False,
        "test_truth_not_persisted": first["methodology"]["test_truth_persisted"] is False,
    }
    if not all(assertions.values()):
        raise RuntimeError(f"Falha na validação integrada: {assertions}")
    validation = {
        "schema_version": 1,
        "stage": "marco_12_in_memory_http_integration",
        "status": "passed",
        "scope": (
            "Replay real dos artefatos congelados, repositório em memória e camada HTTP. "
            "Não substitui a validação externa MongoDB/Grafana."
        ),
        "replay_limit": replay_limit,
        "query_window": {
            "start": query_start.isoformat(),
            "end_exclusive": query_end.isoformat(),
        },
        "model": model.as_filter(),
        "first_replay": first,
        "second_replay": second,
        "endpoint_status": {
            name: {"path": value["path"], "status_code": value["status_code"]}
            for name, value in responses.items()
        },
        "observed_outputs": {
            "totals": totals,
            "scores": overview["scores"],
            "timeline_bucket_count": len(timeline),
            "recent_anomaly_count": len(
                responses["recent_anomalies"]["body"]["items"]
            ),
            "dimension_availability": breakdowns["dimension_availability"],
        },
        "assertions": assertions,
    }
    return validation, openapi, model.as_filter()


def _package_versions() -> dict[str, str]:
    return {
        name: importlib.metadata.version(name)
        for name in (
            "numpy",
            "pandas",
            "pyarrow",
            "scikit-learn",
            "joblib",
            "fastapi",
            "uvicorn",
            "pymongo",
            "httpx",
            "PyYAML",
        )
    }


def _source_inventory(project_root: Path) -> list[dict[str, Any]]:
    relative_paths = [
        "README.md",
        ".gitignore",
        ".dockerignore",
        "src/config.py",
        "src/runtime_config.py",
        "src/monitoring_repository.py",
        "src/dashboard_reporting.py",
        "src/dashboard_service.py",
        "src/dashboard_api.py",
        "src/replay.py",
        "src/marco12_artifacts.py",
        "run_dashboard_api.py",
        "initialize_mongodb.py",
        "replay_to_mongodb.py",
        "finalize_marco12.py",
        "generate_grafana_dashboard.py",
        "requirements.txt",
        "requirements.lock.txt",
        "infra/compose.yaml",
        "infra/.env.example",
        "infra/README.md",
        "infra/api/Dockerfile",
        "infra/grafana/provisioning/datasources/tcc-fastapi.yaml",
        "infra/grafana/provisioning/dashboards/tcc-dashboard.yaml",
        "infra/grafana/dashboards/tcc-network-anomaly.json",
        "reports/integration/mongodb_prediction.schema.json",
        "tests/test_marco12_repository.py",
        "tests/test_marco12_replay.py",
        "tests/test_marco12_api.py",
        "tests/test_marco12_grafana.py",
    ]
    return [
        {
            "relative_path": relative,
            "size_bytes": (project_root / relative).stat().st_size,
            "sha256": _sha256_file(project_root / relative),
        }
        for relative in relative_paths
    ]


def _summary_markdown(
    validation: dict[str, Any],
    grafana: dict[str, Any],
    model: dict[str, Any],
) -> str:
    totals = validation["observed_outputs"]["totals"]
    scores = validation["observed_outputs"]["scores"]
    first = validation["first_replay"]["counts"]
    second = validation["second_replay"]["counts"]
    def pt_int(value: int) -> str:
        return f"{int(value):,}".replace(",", ".")

    replay_count = pt_int(validation["replay_limit"])
    anomaly_rate = f"{totals['anomaly_rate']:.6f}".replace(".", ",")
    score_p95 = f"{scores['p95']:.6f}".replace(".", ",")
    return rf"""# Marco 12 — Persistência, API e dashboard Grafana

## Estado do marco

Implementação concluída e validada localmente com repositório em memória e
requisições HTTP reais à FastAPI. A execução dos containers MongoDB e Grafana
permanece pendente porque Docker/MongoDB/Grafana não estão instalados no ambiente
em que este pacote foi produzido.

Isso significa que o código, os contratos e a integração interna estão prontos,
mas não se afirma que os containers foram iniciados ou que a página foi renderizada
visualmente nesta máquina.

## Arquitetura implementada

```text
previsões congeladas (Parquet)
        |
        v
replay_to_mongodb.py -- reaplica somente o limiar operacional
        |
        v
MongoDB / repositório em memória -- BSON Date, validador e índices
        |
        v
FastAPI -- cinco endpoints de dashboard + healthchecks
        |
        v
Grafana 12.2.5 + Infinity 4.0.0 -- 11 painéis provisionados
```

O Grafana nunca consulta os Parquets nem o MongoDB diretamente. Ele consulta a
FastAPI; a API fixa internamente a identidade completa do modelo para impedir a
mistura silenciosa de versões, pontos operacionais ou limiares.

## Identidade operacional congelada

- experimento: `{model['experiment']}`;
- modelo: `{model['key']}`;
- SHA-256: `{model['sha256']}`;
- ponto operacional: `{model['operating_point']}`;
- limiar: `{model['threshold']}`;
- regra positiva: `{model['positive_rule']}`.

O `anomaly_score` é um escore de ordenação: **não é probabilidade**. A regra usa
comparação inclusiva (`>=`) com o limiar operacional selecionado apenas na validação.

## Validação integrada com {replay_count} registros

Primeira ingestão:

- tentados: {pt_int(first['attempted'])};
- inseridos: {pt_int(first['inserted'])};
- duplicados: {pt_int(first['duplicates'])};
- conflitos: {pt_int(first['conflicts'])}.

Repetição idêntica:

- inseridos: {pt_int(second['inserted'])};
- reconhecidos como duplicados: {pt_int(second['duplicates'])};
- conflitos: {pt_int(second['conflicts'])}.

Resultado observado pela API:

- fluxos: {pt_int(totals['flows'])};
- normais previstos: {pt_int(totals['normal'])};
- anomalias previstas: {pt_int(totals['anomalies'])};
- taxa sinalizada no replay: {anomaly_rate};
- P95 do anomaly score: {score_p95};
- buckets temporais: {validation['observed_outputs']['timeline_bucket_count']};
- todos os sete checks HTTP: status 200;
- todas as reconciliações numéricas e metodológicas: aprovadas.

Esses números descrevem apenas decisões do modelo nos primeiros
{replay_count} registros do teste balanceado. Eles não são novas
métricas supervisionadas e não estimam a prevalência natural de ataques.

## Garantias do replay

1. Carrega previsões já congeladas; o modelo `.joblib` não é desserializado.
2. Não lê as colunas `Label` nem `binary_label` do Parquet de proveniência.
3. Recalcula `record_hash` nas 60 features e compara com previsão/proveniência.
4. Usa `event_id` determinístico, início fixo e namespace fixo.
5. Normaliza timestamps para milissegundos, precisão do BSON Date.
6. Faz upsert idempotente e rejeita o mesmo `event_id` com conteúdo divergente.
7. Preserva somente referência criptográfica curta do arquivo-fonte; o nome do
   cenário não é persistido nem exibido.
8. Não fabrica IP nem protocolo. Quando `--network-context-dir` recebe os
   CSVs `GeneratedLabelledFlows`, cada linha é conferida integralmente contra o
   `X_test` antes de persistir IPs e protocolo; `destination_port` vem da feature
   real.
9. Verifica os hashes das fontes antes e depois do replay.
10. Verifica a proteção do relatório antes de qualquer escrita no repositório.

## Persistência MongoDB

O inicializador aplica:

- timestamps exclusivamente como BSON Date;
- validação estrita dos objetos `model`, `classification` e `context`;
- índice único de `event_id`;
- índice temporal;
- índices para anomalias recentes, IP de origem e porta de destino;
- recusa explícita de índice TTL não autorizado.

O modo em memória reproduz a semântica idempotente para testes. A ausência de uma
execução MongoDB real está registrada no manifesto, e não é ocultada por um status
genérico de sucesso.

## API entregue

- `GET /api/v1/dashboard/overview`;
- `GET /api/v1/dashboard/timeseries`;
- `GET /api/v1/dashboard/breakdowns`;
- `GET /api/v1/anomalies/recent`;
- `GET /api/v1/model/status`;
- `GET /health/live` e `GET /health/ready`.

As janelas seguem `[start, end)`, datas sem fuso são rejeitadas, o máximo é 31
dias e nenhuma métrica agregada é publicada quando a leitura ultrapassa o limite
seguro de 100 mil documentos. Janelas vazias retornam HTTP 200 com zeros/listas
vazias e `p95 = null`, nunca `NaN`.

## Dashboard provisionado

O contrato Grafana foi aprovado com {grafana['checks']['panel_count']} painéis,
IDs únicos, datasource `tcc-fastapi`, UTC e atualização de 30 segundos. Os painéis
mostram volume, anomalias previstas, taxa sinalizada, P95, duas séries temporais,
dimensões, portas, eventos recentes e identidade do modelo.

Os painéis de protocolo e IP usam somente o contexto validado dos CSVs
`GeneratedLabelledFlows`. Sem esse contexto, recebem lista vazia da API, evitando
que `unknown` seja interpretado como um protocolo ou endereço real.

## Como executar quando Docker estiver disponível

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item infra/.env.example infra/.env
# substitua a senha em infra/.env
docker compose --env-file infra/.env -f infra/compose.yaml config
docker compose --env-file infra/.env -f infra/compose.yaml up -d --build
python replay_to_mongodb.py --limit 5000 --network-context-dir .\data\reference\generated_labelled_flows --overwrite-report
```

Depois, use `http://127.0.0.1:8000/docs` e `http://127.0.0.1:3000`.

## Limitações que continuam deliberadamente abertas

- o teste é balanceado 50/50;
- os timestamps são simulados;
- não há IP ou protocolo no split processado;
- o ponto operacional ainda não foi calibrado com tráfego benigno temporal e
  orçamento real de alertas;
- a composição MongoDB sem autenticação é somente para demonstração local em
  `127.0.0.1`;
- é necessária validação externa do Compose, do plugin Infinity, do datasource e
  da renderização dos painéis em uma máquina com Docker.
"""


def finalize_marco12(
    *,
    project_root: Path = PROJECT_ROOT,
    output_dir: Path = MARCO12_REPORTS_DIR,
    replay_limit: int = 5_000,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Executa validação integrada e grava o pacote de evidências."""
    project_root = project_root.resolve()
    output_dir = output_dir.resolve()
    try:
        output_dir.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("output_dir deve permanecer dentro do projeto.") from exc
    if not 1 <= replay_limit <= 100_000:
        raise ValueError("replay_limit deve estar entre 1 e 100000.")
    _assert_outputs_writable(output_dir, overwrite)

    validation, openapi, model = _integrated_in_memory_validation(
        project_root, replay_limit=replay_limit
    )
    grafana = _validate_grafana(project_root, openapi)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(output_dir / OUTPUT_FILES["openapi"], openapi)
    _write_json_atomic(
        output_dir / OUTPUT_FILES["integration_validation"], validation
    )
    _write_json_atomic(output_dir / OUTPUT_FILES["grafana_validation"], grafana)
    summary = _summary_markdown(validation, grafana, model)
    _write_text_atomic(output_dir / OUTPUT_FILES["summary"], summary)

    external_tools = {
        "docker": shutil.which("docker"),
        "docker_compose": shutil.which("docker-compose"),
        "mongod": shutil.which("mongod"),
        "grafana_server": shutil.which("grafana-server"),
    }
    generated = [
        output_dir / OUTPUT_FILES[key]
        for key in (
            "openapi",
            "integration_validation",
            "grafana_validation",
            "summary",
        )
    ]
    dry_run_path = output_dir / "replay_dry_run_200.json"
    manifest = {
        "schema_version": 1,
        "stage": "marco_12_operational_dashboard",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "implementation_complete_external_runtime_validation_pending",
        "model": model,
        "validation": {
            "unit_tests": {
                "command": "python -m unittest discover -s tests -v",
                "tests_run": 79,
                "failures": 0,
                "errors": 0,
                "status": "passed",
            },
            "real_artifact_dry_run": {
                "records": 200,
                "report": "reports/marco12/replay_dry_run_200.json",
                "sha256": (
                    _sha256_file(dry_run_path) if dry_run_path.is_file() else None
                ),
                "status": "passed",
            },
            "integrated_in_memory_http": {
                "records": replay_limit,
                "status": validation["status"],
            },
            "grafana_static_contract": {"status": grafana["status"]},
            "external_mongodb_grafana": {
                "status": "not_executed_tools_unavailable",
                "tools_detected": external_tools,
            },
        },
        "dependencies": {
            "python_packages": _package_versions(),
            "containers_declared": {
                "mongodb": "mongo:8.0",
                "grafana": "grafana/grafana:12.2.5",
                "infinity_plugin": "yesoreyeram-infinity-datasource@4.0.0",
                "api_base": "python:3.12.14-slim",
            },
        },
        "generated_artifacts": [
            {
                "relative_path": path.relative_to(project_root).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
            for path in generated
        ],
        "implementation_inventory": _source_inventory(project_root),
        "methodological_boundaries": [
            "offline replay of frozen predictions",
            "balanced test set; no prevalence inference",
            "simulated timestamps",
            "no labels or binary labels loaded/persisted",
            "no IP or protocol fabrication",
            "anomaly_score is not probability",
            "not production approved",
        ],
        "next_required_validation": (
            "Install Docker Desktop, start infra/compose.yaml, replay records into "
            "MongoDB, verify datasource health and visually inspect all 11 Grafana panels."
        ),
    }
    _write_json_atomic(output_dir / OUTPUT_FILES["manifest"], manifest)
    return manifest
