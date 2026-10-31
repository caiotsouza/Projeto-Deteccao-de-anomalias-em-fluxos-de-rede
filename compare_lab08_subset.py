"""Compara exports LAB08 com a matriz benigna, sem carregar modelos."""
import argparse
import json
from pathlib import Path

from src.config import PROJECT_ROOT
from src.lab_flow_audit import sha256
from src.lab_v4_adapter import summarize_predictions

MODELS = ('isolation_forest', 'lof')
SCENARIOS = {
    'lab03_small': 'LAB03 — HTTP pequeno',
    'lab04_medium': 'LAB04 — HTTP médio',
    'lab05_slow': 'LAB05 — limite no cliente',
    'lab06_serverpaced': 'LAB06 — controle no servidor',
}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def identity(manifest):
    return {m: {k: manifest['models'][m][k] for k in ('model_sha256', 'operating_point', 'threshold')}
            for m in MODELS}


def checked_run(directory, expected_identity):
    manifest = read(directory / 'run_manifest.json')
    if manifest['status'] != 'exploratory_inference_completed' or identity(manifest) != expected_identity:
        raise ValueError('Rodada incompleta ou modelos/limiares divergentes.')
    for filename, digest in manifest['output_sha256'].items():
        path = (directory / filename).resolve()
        if path.parent != directory.resolve() or sha256(path) != digest:
            raise ValueError('Saida alterada ou caminho inseguro.')
    predictions = {m: read(directory / (m + '_predictions.json')) for m in MODELS}
    inputs = read(directory / 'model_inputs.json')
    ids = [x['event_id'] for x in inputs]
    for model, rows in predictions.items():
        if [x['event_id'] for x in rows] != ids or summarize_predictions(rows) != manifest['models'][model]['summary']:
            raise ValueError('Resumo ou ordem de predicoes inconsistente.')
    return manifest, predictions


def aggregate(entries):
    models = {}
    for model in MODELS:
        models[model] = {}
        for label in ('all_segments', 'with_payload', 'zero_payload'):
            n = sum(e[model][label]['segments'] for e in entries)
            flagged = sum(e[model][label]['signaled_segments'] for e in entries)
            models[model][label] = dict(segments=n, signaled_segments=flagged,
                                        signal_rate=flagged / n if n else None)
    if models[MODELS[0]]['all_segments']['segments'] != models[MODELS[1]]['all_segments']['segments']:
        raise ValueError('Denominadores diferentes entre modelos.')
    return models


def compare(root=PROJECT_ROOT):
    snapshot_path = root / 'reports/lab/lab_capture_summary_complete_r1_r3.json'
    snapshot = read(snapshot_path)
    fixed = snapshot['fixed_model_identity']
    provenance = {str(snapshot_path.relative_to(root)): sha256(snapshot_path)}
    rows = []
    for prefix, title in SCENARIOS.items():
        entries = []
        for repetition in (1, 2, 3):
            session = snapshot['sessions'][prefix + '_r' + str(repetition)]
            path = (root / session['run_manifest_relative_path']).resolve()
            if not path.is_relative_to(root.resolve()) or sha256(path) != session['run_manifest_sha256']:
                raise ValueError('Manifesto benigno alterado ou fora da raiz.')
            report, _ = checked_run(path.parent, fixed)
            if {m: report['models'][m]['summary'] for m in MODELS} != session['models']:
                raise ValueError('Snapshot diverge da rodada benigna.')
            provenance[str(path.relative_to(root))] = sha256(path)
            entries.append(session['models'])
        rows.append(dict(scenario=prefix, title=title, sessions=3, population='benign_synthetic_http_exports',
                         models=aggregate(entries)))
    folder = root / 'data/lab/lab08_tcp_responsive/r1/inference_exported_subset'
    report, predictions = checked_run(folder, fixed)
    scope = report['methodology']['evaluation_scope']
    if (scope['population'] != 'exported_records_only' or not scope['partial_export_explicitly_accepted']
            or scope['whole_scan_detection_measured'] or scope['coverage']['full_packet_coverage']):
        raise ValueError('Escopo LAB08 nao e o recorte parcial autorizado.')
    coverage_path = root / 'data/lab/lab08_tcp_responsive/r1/extraction_audit.json'
    if (sha256(coverage_path) != report['methodology']['coverage_audit_sha256']
            or read(coverage_path)['coverage'] != scope['coverage']):
        raise ValueError('Auditoria de cobertura alterada.')
    provenance[str((folder / 'run_manifest.json').relative_to(root))] = sha256(folder / 'run_manifest.json')
    provenance[str(coverage_path.relative_to(root))] = sha256(coverage_path)
    rows.append(dict(scenario='lab08_r1_partial_export_only', title='LAB08 — reconhecimento, recorte exportado',
                     sessions=1, population='exported_records_only',
                     models=aggregate([{m: report['models'][m]['summary'] for m in MODELS}])))
    details = []
    for first, second in zip(predictions[MODELS[0]], predictions[MODELS[1]]):
        details.append(dict(csv_data_row=first['context']['csv_data_row'],
                            source_port=first['context']['src_port'], target_port=first['context']['dst_port'],
                            isolation_forest=first['prediction'], lof=second['prediction']))
    return dict(status='restricted_descriptive_comparison_completed', fixed_model_identity=fixed,
                comparison_rows=rows, lab08_evaluation_scope=scope, lab08_records=details,
                source_sha256=provenance, models_loaded_by_comparison=False,
                models_retrained=False, thresholds_recalibrated=False, database_written=False,
                supervised_metrics_computed=False, implementation_sha256=sha256(Path(__file__)))


def markdown(result):
    lines = ['# Comparativo exploratório — tráfego benigno e recorte LAB08', '',
             '## Resultado consolidado', '',
             'Contagens no ponto operacional `validation_fpr_operational`. Denominador: registros',
             'exportados pelo V4, não pacotes, ataques independentes ou tentativas totais.', '',
             '| Cenário | Sessões | Registros | IF sinalizados | LOF sinalizados |',
             '| --- | ---: | ---: | ---: | ---: |']
    for row in result['comparison_rows']:
        a, b = (row['models'][m]['all_segments'] for m in MODELS)
        lines.append(f"| {row['title']} | {row['sessions']} | {a['segments']} | "
                     f"{a['signaled_segments']}/{a['segments']} | {b['signaled_segments']}/{b['segments']} |")
    lines += ['', 'As quatro linhas benignas reúnem três repetições cada; LAB08 contém uma única',
              'sessão e somente os quatro registros exportados. Não são amostras balanceadas.',
              'Não somar cenários heterogêneos para anunciar um índice geral de desempenho.', '',
              '## Os quatro registros do reconhecimento', '',
              '| Linha CSV | Porta origem Kali | Porta destino Windows | Score IF | IF sinaliza | Score LOF | LOF sinaliza |',
              '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for row in result['lab08_records']:
        a, b = row['isolation_forest'], row['lof']
        lines.append(f"| {row['csv_data_row']} | {row['source_port']} | {row['target_port']} | "
                     f"{a['anomaly_score']:.6f} | {a['predicted_anomaly']} | {b['anomaly_score']:.6f} | {b['predicted_anomaly']} |")
    lines += ['', 'Limiares congelados: IF 0,615824439899627; LOF 91,08685969933371.',
              'A decisão é score >= limiar. Scores não são probabilidades e suas escalas',
              'não devem ser comparadas diretamente entre os modelos. O LOF nativo sinalizou',
              '4/4, mas no limiar operacional sinalizou 1/4; o comparativo usa apenas o operacional.', '',
              '## Cobertura e limites da conclusão', '',
              '- LAB08: 42 pacotes, 30 grupos de endpoints; CSV representa 16 pacotes (38,10%)',
              '  em quatro grupos (13,33%). Os 26 grupos de um SYN não foram exportados.',
              '- Nenhuma predição foi produzida para os grupos não exportados. A auditoria',
              '  original de extração parcial permanece intacta; a nova autorização está no',
              '  manifesto de inferência e em cada registro de entrada/saída.',
              '- Os quatro registros não têm payload. LAB03–LAB06 incluem registros com',
              '  payload e segmentos finais sem payload; a segmentação afeta a comparação.',
              '- A divergência semântica entre o V4 e as features históricas, especialmente',
              '  as flags, continua não resolvida. Não houve clipping, imputação ou ajuste',
              '  dos modelos para melhorar o resultado.',
              '- Atividade de reconhecimento conhecida no nível da sessão não equivale a',
              '  rotulagem independente de cada segmento. Não se calculam precisão, recall,',
              '  F1, FPR, acurácia ou taxa de detecção da sondagem inteira.',
              '- Os modelos analisam registros individuais; este ensaio não valida um',
              '  detector temporal que correlacione todas as portas da varredura.',
              '- Um único cenário de reconhecimento não representa força bruta, malware,',
              '  exploração ou negação de serviço. A proteção do firewall e os alertas de',
              '  aprendizado de máquina são resultados distintos.', '',
              '## Discussão para o artigo', '',
              'Nos cenários HTTP sintéticos, o Isolation Forest apresentou menor sinalização',
              'que o LOF, incluindo ausência de alertas nos cenários de arquivos pequenos e',
              'médios. Entretanto, no recorte exportado da sessão de reconhecimento, o',
              'Isolation Forest não sinalizou nenhum dos quatro registros, enquanto o LOF',
              'sinalizou um. Esse contraste evidencia que menor sinalização no tráfego benigno',
              'não demonstra, isoladamente, maior capacidade de identificar atividades de',
              'reconhecimento. A cobertura parcial da extração, a amostra reduzida e as',
              'diferenças de representação das features impedem estabelecer superioridade',
              'geral entre os modelos ou estimar a detecção da varredura completa. Os',
              'resultados devem ser apresentados como avaliação exploratória de transferência',
              'dos modelos treinados no CIC-IDS2017 para capturas controladas do laboratório.', '',
              '## Rastreabilidade', '',
              'O JSON homônimo contém hashes dos manifestos e da auditoria, identidade dos',
              'modelos, ponto operacional, contagens por grupo de payload e decisões individuais.',
              'Os hashes das saídas foram conferidos antes da consolidação. Nenhuma predição',
              'benigna foi refeita ou alterada. Não houve treino, calibração ou escrita em banco.',
              'As divergências já conhecidas dos JSONs auxiliares de metadados permanecem',
              'registradas no manifesto; esses JSONs não são usados para inferência. Os hashes',
              'dos modelos joblib foram verificados. Avisos de localização do Python e WMIC',
              'não impediram a execução; o manifesto registra as versões do ambiente.', '',
              'Para reproduzir em saída nova: `python compare_lab08_subset.py --output-prefix',
              'reports/lab/lab08_subset_comparison_recheck` (comando em uma única linha).', '']
    return '\n'.join(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-prefix', type=Path, required=True)
    args = parser.parse_args()
    paths = [args.output_prefix.with_suffix(ext) for ext in ('.json', '.md')]
    if any(p.exists() for p in paths):
        raise FileExistsError('Escolha prefixo novo; resultados nao sao sobrescritos.')
    result = compare()
    for path, payload in zip(paths, (json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n', markdown(result))):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            stream.write(payload)
    print(json.dumps(result['comparison_rows'], indent=2, ensure_ascii=False))
