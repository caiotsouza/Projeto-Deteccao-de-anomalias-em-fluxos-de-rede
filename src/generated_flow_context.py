"""Recupera contexto de rede real dos CSVs GeneratedLabelledFlows.

O split de modelagem foi produzido a partir dos CSVs MachineLearningCSV, que
removem identificadores de fluxo. Este módulo recupera somente IPs e protocolo
da versão GeneratedLabelledFlows, mas falha se as features da mesma linha não
forem exatamente iguais às usadas no ``X_test``. Assim, o dashboard nunca
associa metadados de um fluxo a outro por suposição.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from src.utils import normalize_columns


REQUIRED_CONTEXT_COLUMNS = ("source_ip", "destination_ip", "protocol")
SUPPORTED_ENCODINGS = ("utf-8", "latin-1")
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


@dataclass(frozen=True)
class FlowNetworkContext:
    """Metadados de rede validados para um único fluxo do replay."""

    src_ip: str
    dst_ip: str
    protocol: str


@dataclass(frozen=True)
class ResolvedFlowContexts:
    """Resultado auditável da associação entre split e fluxos rotulados."""

    by_position: Mapping[int, FlowNetworkContext]
    source_paths: tuple[Path, ...]

    @property
    def records_validated(self) -> int:
        return len(self.by_position)


class GeneratedFlowContextResolver:
    """Resolve IPs e protocolo sem ler rótulos nem alterar o conjunto de teste."""

    def __init__(
        self,
        reference_dir: Path,
        feature_columns: Sequence[str],
        *,
        chunk_size: int = 100_000,
    ) -> None:
        self.reference_dir = Path(reference_dir).resolve()
        self.feature_columns = tuple(str(column) for column in feature_columns)
        self.chunk_size = int(chunk_size)
        if not self.reference_dir.is_dir():
            raise FileNotFoundError(
                "Diretório de GeneratedLabelledFlows não encontrado: "
                f"{self.reference_dir}"
            )
        if not self.feature_columns:
            raise ValueError("Ao menos uma feature deve ser informada para validação.")
        if len(set(self.feature_columns)) != len(self.feature_columns):
            raise ValueError("As features de validação possuem nomes duplicados.")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size deve ser positivo.")

    @staticmethod
    def _normalise_source_file(value: object) -> str:
        source_file = str(value).strip()
        if not source_file or Path(source_file).name != source_file:
            raise ValueError(
                "source_file da proveniência deve conter somente o nome do CSV."
            )
        return source_file

    @staticmethod
    def _normalise_source_row(value: object) -> int:
        if isinstance(value, bool):
            raise ValueError("source_row inválido na proveniência.")
        try:
            source_row = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("source_row inválido na proveniência.") from exc
        if source_row < 0 or float(value) != float(source_row):
            raise ValueError("source_row deve ser um inteiro não negativo.")
        return source_row

    def _requests_by_source(
        self,
        provenance: pd.DataFrame,
        positions: Iterable[int],
    ) -> dict[str, list[tuple[int, int]]]:
        required = {"source_file", "source_row"}
        missing = sorted(required - set(provenance.columns))
        if missing:
            raise ValueError(f"Proveniência sem colunas obrigatórias: {missing}")
        requests: dict[str, list[tuple[int, int]]] = {}
        seen: set[tuple[str, int]] = set()
        for position in positions:
            if position < 0 or position >= len(provenance):
                raise ValueError("Posição solicitada está fora da proveniência.")
            row = provenance.iloc[position]
            source_file = self._normalise_source_file(row["source_file"])
            source_row = self._normalise_source_row(row["source_row"])
            key = (source_file, source_row)
            if key in seen:
                raise ValueError(
                    "A proveniência associa mais de uma posição à mesma linha fonte: "
                    f"{source_file}:{source_row}."
                )
            seen.add(key)
            requests.setdefault(source_file, []).append((source_row, int(position)))
        for entries in requests.values():
            entries.sort()
        return requests

    def source_paths_for(
        self,
        provenance: pd.DataFrame,
        positions: Iterable[int],
    ) -> tuple[Path, ...]:
        requests = self._requests_by_source(provenance, positions)
        paths: list[Path] = []
        for source_file in sorted(requests):
            path = (self.reference_dir / source_file).resolve()
            try:
                path.relative_to(self.reference_dir)
            except ValueError as exc:
                raise ValueError("CSV de contexto fora do diretório permitido.") from exc
            if not path.is_file():
                raise FileNotFoundError(
                    "CSV GeneratedLabelledFlows ausente para a proveniência: "
                    f"{source_file}"
                )
            paths.append(path)
        return tuple(paths)

    def _readable_columns(self, path: Path) -> list[str]:
        # A distribuicao oficial do CIC-IDS2017 possui ao menos um CSV em
        # Windows-1252/Latin-1. Latin-1 e usado somente se o UTF-8 falhar;
        # isso preserva os bytes e nao altera as colunas numericas validadas.
        header = None
        for encoding in SUPPORTED_ENCODINGS:
            try:
                header = pd.read_csv(path, nrows=0, encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
        if header is None:
            raise ValueError(f"Não foi possível decodificar o CSV: {path.name}")
        normalized = normalize_columns(list(header.columns))
        required = set(self.feature_columns) | set(REQUIRED_CONTEXT_COLUMNS)
        missing = sorted(required - set(normalized))
        if missing:
            raise ValueError(
                f"CSV GeneratedLabelledFlows sem colunas necessárias em {path.name}: "
                f"{missing}"
            )
        return [
            original
            for original, normalized_name in zip(header.columns, normalized)
            if normalized_name in required
        ]

    def _resolve_source_contexts(
        self,
        path: Path,
        requested: list[tuple[int, int]],
        usecols: list[str],
        features: pd.DataFrame,
    ) -> dict[int, FlowNetworkContext]:
        """Lê um CSV com fallback de codificação sem aceitar contexto parcial."""
        last_decode_error: UnicodeDecodeError | None = None
        for encoding in SUPPORTED_ENCODINGS:
            contexts: dict[int, FlowNetworkContext] = {}
            cursor = 0
            row_offset = 0
            try:
                with pd.read_csv(
                    path,
                    usecols=usecols,
                    chunksize=self.chunk_size,
                    low_memory=False,
                    encoding=encoding,
                ) as reader:
                    for chunk in reader:
                        chunk.columns = normalize_columns(list(chunk.columns))
                        chunk_end = row_offset + len(chunk)
                        while (
                            cursor < len(requested)
                            and requested[cursor][0] < chunk_end
                        ):
                            source_row, position = requested[cursor]
                            if source_row >= row_offset:
                                reference_row = chunk.iloc[source_row - row_offset]
                                self._validate_feature_equivalence(
                                    reference_row,
                                    features,
                                    position,
                                    path.name,
                                    source_row,
                                )
                                contexts[position] = FlowNetworkContext(
                                    src_ip=self._validated_ip(
                                        reference_row["source_ip"],
                                        "source_ip",
                                        path.name,
                                        source_row,
                                    ),
                                    dst_ip=self._validated_ip(
                                        reference_row["destination_ip"],
                                        "destination_ip",
                                        path.name,
                                        source_row,
                                    ),
                                    protocol=self._validated_protocol(
                                        reference_row["protocol"],
                                        path.name,
                                        source_row,
                                    ),
                                )
                            cursor += 1
                        row_offset = chunk_end
                        if cursor == len(requested):
                            break
            except UnicodeDecodeError as exc:
                last_decode_error = exc
                continue
            if cursor != len(requested):
                next_source_row = requested[cursor][0]
                raise ValueError(
                    "source_row não existe no GeneratedLabelledFlows: "
                    f"{path.name}:{next_source_row}."
                )
            return contexts
        raise ValueError(
            f"Não foi possível decodificar o CSV: {path.name}"
        ) from last_decode_error

    @staticmethod
    def _validated_ip(value: object, field: str, source_file: str, source_row: int) -> str:
        text = str(value).strip()
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise ValueError(
                f"{field} inválido em {source_file}:{source_row}: {value!r}"
            ) from exc

    @staticmethod
    def _validated_protocol(value: object, source_file: str, source_row: int) -> str:
        text = str(value).strip()
        if not text or text.lower() in {"nan", "none", "null"}:
            raise ValueError(
                f"protocol ausente em {source_file}:{source_row}."
            )
        try:
            numeric = float(text)
        except ValueError:
            return text
        if not math.isfinite(numeric) or numeric != int(numeric):
            raise ValueError(
                f"protocol inválido em {source_file}:{source_row}: {value!r}"
            )
        number = int(numeric)
        if not 0 <= number <= 255:
            raise ValueError(
                f"protocol fora do intervalo IP em {source_file}:{source_row}: {number}"
            )
        return PROTOCOL_NAMES.get(number, f"IP-{number}")

    def _validate_feature_equivalence(
        self,
        reference_row: pd.Series,
        features: pd.DataFrame,
        position: int,
        source_file: str,
        source_row: int,
    ) -> None:
        candidate = pd.to_numeric(
            reference_row.loc[list(self.feature_columns)], errors="coerce"
        )
        expected = pd.to_numeric(
            features.iloc[position].loc[list(self.feature_columns)], errors="raise"
        )
        candidate_values = candidate.to_numpy(dtype=np.float64)
        expected_values = expected.to_numpy(dtype=np.float64)
        if not np.isfinite(candidate_values).all() or not np.isfinite(expected_values).all():
            raise ValueError(
                "Features não finitas impedem validar o contexto de "
                f"{source_file}:{source_row}."
            )
        if not np.array_equal(candidate_values, expected_values):
            raise ValueError(
                "As features do GeneratedLabelledFlows não correspondem ao X_test em "
                f"{source_file}:{source_row}; associação de contexto interrompida."
            )

    def resolve(
        self,
        features: pd.DataFrame,
        provenance: pd.DataFrame,
        positions: Iterable[int],
    ) -> ResolvedFlowContexts:
        """Lê apenas o contexto necessário e valida cada linha antes de retorná-la."""
        requests = self._requests_by_source(provenance, positions)
        if not requests:
            raise ValueError("Nenhuma posição foi solicitada para contexto de rede.")
        missing_features = sorted(set(self.feature_columns) - set(features.columns))
        if missing_features:
            raise ValueError(
                f"X_test sem features necessárias para validação: {missing_features}"
            )

        contexts: dict[int, FlowNetworkContext] = {}
        source_paths = self.source_paths_for(provenance, positions)
        for path in source_paths:
            source_file = path.name
            requested = requests[source_file]
            usecols = self._readable_columns(path)
            contexts.update(
                self._resolve_source_contexts(path, requested, usecols, features)
            )

        if len(contexts) != sum(len(entries) for entries in requests.values()):
            raise RuntimeError("Nem todos os contextos de rede foram resolvidos.")
        return ResolvedFlowContexts(contexts, source_paths)
