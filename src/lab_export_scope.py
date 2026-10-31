"""Escopo explicito de uma analise condicionada aos registros exportados."""


def validate_export_scope(audit, structural, records, independent, *, accept_partial_export=False):
    if audit['structural_audit'] != structural:
        raise ValueError('Auditoria de cobertura pertence a outra extracao.')
    groups = {(tuple(g['source']), tuple(g['destination'])): g for g in independent['connections']}
    represented = set()
    for row in records:
        c, f = row['context'], row['features']
        key = ((c['src_ip'], c['src_port']), (c['dst_ip'], c['dst_port']))
        if key not in groups or key in represented:
            raise ValueError('Grupo exportado ausente/duplicado na auditoria independente.')
        g = groups[key]
        if (f['total_fwd_packets'] != g['forward_packets']
                or f['total_backward_packets'] != g['backward_packets']
                or f['flow_duration'] != g['duration_us']
                or c['packet_count'] != g['packets']):
            raise ValueError('Registro exportado diverge do grupo no PCAP.')
        represented.add(key)
    missing = [g for key, g in groups.items() if key not in represented]
    represented_packets = sum(groups[key]['packets'] for key in represented)
    expected = {
        'captured_packets': independent['packets'], 'represented_packets': represented_packets,
        'unrepresented_packets': independent['packets'] - represented_packets,
        'captured_endpoint_groups': len(groups), 'represented_endpoint_groups': len(represented),
        'unrepresented_endpoint_groups': len(missing),
        'all_unrepresented_groups_are_single_packet': bool(missing) and all(g['packets'] == 1 for g in missing),
        'full_packet_coverage': represented_packets == independent['packets'],
        'unrepresented_groups': missing,
    }
    if audit['coverage'] != expected or len(records) != structural['rows']:
        raise ValueError('Cobertura declarada nao corresponde ao PCAP e aos registros.')
    if not expected['full_packet_coverage'] and not accept_partial_export:
        raise ValueError('Analise parcial exige autorizacao explicita --accept-partial-export.')
    return {
        'population': 'exported_records_only', 'denominator_records': len(records),
        'partial_export_explicitly_accepted': bool(accept_partial_export),
        'coverage': expected,
        'whole_scan_detection_measured': False,
        'limitations': [
            'Selection is conditional on extractor export, not on model scores.',
            'No inference is produced for unrepresented packets/groups.',
            'No precision, recall, FPR, F1 or whole-scan detection estimate is computed.',
            'A small set of correlated exported records is not an independent attack sample.',
        ],
    }
