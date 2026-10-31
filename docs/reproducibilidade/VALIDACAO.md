# Validação da cópia pública — 31/10/2026

A suíte `python -m unittest discover -s tests -q` concluiu os 162 testes com
resultado `OK`, tanto no projeto local quanto na cópia selecionada para
publicação. O ambiente utilizado foi a `.venv` local do projeto, Python 3.14.7.
Essa execução testa o código e os contratos automatizados; não constitui novo
treinamento do benchmark nem validação de eficácia em produção.

Os testes precisaram de permissão para utilizar diretórios temporários e HTTP
local. Uma execução anterior dentro do ambiente restrito encontrou erros de
permissão e foi interrompida. Na execução concluída permaneceram avisos de
descontinuação de Starlette/httpx e Joblib/NumPy, sem falhas da suíte. Não foi
feita atualização de dependências durante esta revisão.

O documento revisado foi renderizado pelo Word e suas 28 páginas foram
inspecionadas visualmente. O DOCX de origem foi preservado. Os estilos e a
geometria do documento foram mantidos; não se certifica conformidade com um
manual institucional não fornecido.

O manifesto `publication_manifest.json` registra os hashes das cópias
distribuídas. Execute `python tools/verify_publication.py` para verificá-los.
O arquivo `.gitattributes` desativa conversões automáticas de fim de linha,
para que um checkout não altere os bytes publicados.

Os arquivos CSV/Parquet, modelos e PCAPs foram mantidos byte a byte. Alguns
metadados textuais tiveram caminhos pessoais substituídos e formatação JSON
normalizada; por isso seus hashes publicados podem diferir dos históricos.
As duas identidades constam do manifesto. Referências a hashes históricos em
relatórios antigos não foram reescritas para simular identidade com as cópias
redigidas. Use o manifesto de publicação para conferir a distribuição atual.

As 14 capturas selecionadas passaram por triagem de endpoints IPv4 do laboratório
e dos cabeçalhos de credenciais procurados. Foram excluídos `.env`, áudio,
parecer privado, ambientes virtuais, caches e imagens de desktop. A triagem
automatizada não substitui uma auditoria forense completa. Os CSVs originais da
base pública devem ser obtidos na fonte oficial indicada no guia.
