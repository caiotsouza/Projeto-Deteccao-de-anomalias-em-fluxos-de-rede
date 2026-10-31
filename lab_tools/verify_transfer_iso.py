"""Confere a ISO plana de transferencia por leitura independente, sem monta-la."""

import argparse
import hashlib
import json
from pathlib import Path


def verify(iso_path: Path, source: Path) -> dict:
    if source.name not in {'prepare_http_payloads.py', 'lab06_server.py'}:
        raise ValueError('Somente os scripts explicitos do laboratorio sao autorizados.')
    data = iso_path.read_bytes()
    block_size = 2048
    joliet = None
    descriptors = []
    for number in range(16, 48):
        descriptor = data[number * block_size:(number + 1) * block_size]
        if len(descriptor) != block_size or descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            raise ValueError("Descritor ISO9660 invalido.")
        kind = descriptor[0]
        descriptors.append(kind)
        if kind == 0:
            raise ValueError("A imagem de transferencia nao deve conter boot record.")
        if kind == 2 and descriptor[88:91] in (b"%/@", b"%/C", b"%/E"):
            joliet = descriptor
        if kind == 255:
            break
    if not descriptors or descriptors[-1] != 255 or joliet is None:
        raise ValueError("Descritores incompletos ou Joliet ausente.")
    if int.from_bytes(joliet[128:130], "little") != block_size:
        raise ValueError("Tamanho de bloco inesperado.")
    root = joliet[156:190]
    start = int.from_bytes(root[2:6], "little") * block_size
    length = int.from_bytes(root[10:14], "little")
    directory = data[start:start + length]
    if len(directory) != length:
        raise ValueError("Diretorio raiz truncado.")
    files = []
    position = 0
    while position < length:
        record_size = directory[position]
        if record_size == 0:
            position = (position // block_size + 1) * block_size
            continue
        record = directory[position:position + record_size]
        if len(record) != record_size or record_size < 34:
            raise ValueError("Registro de diretorio invalido.")
        position += record_size
        raw_name = record[33:33 + record[32]]
        if raw_name in (b"\x00", b"\x01"):
            continue
        if record[25] & 2:
            raise ValueError("Diretorio adicional inesperado na ISO.")
        name = raw_name.decode("utf-16-be").removesuffix(";1")
        extent = int.from_bytes(record[2:6], "little") * block_size
        size = int.from_bytes(record[10:14], "little")
        content = data[extent:extent + size]
        if len(content) != size:
            raise ValueError("Arquivo truncado na ISO.")
        if name != source.name or content != source.read_bytes():
            raise ValueError("Nome ou conteudo diverge do unico script autorizado.")
        compile(content, name, "exec")  # Confere sintaxe sem executar o script.
        files.append({"name": name, "size_bytes": size,
                      "sha256": hashlib.sha256(content).hexdigest()})
    if len(files) != 1:
        raise ValueError("A ISO deve conter exatamente um arquivo.")
    return {"status": "verified", "iso_size_bytes": len(data),
            "iso_sha256": hashlib.sha256(data).hexdigest(),
            "readback_method": "independent Joliet directory parser; no mounting or execution",
            "boot_record_present": False, "files": files,
            "source_byte_identical": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.iso, args.source)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))
