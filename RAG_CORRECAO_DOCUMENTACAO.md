# Sistema RAG Corrigido - Eliminação da Contaminação entre Documentos

## Problema Original
O sistema RAG anterior tinha contaminação entre documentos: quando se perguntava sobre um ficheiro específico, o agente retornava resultados de outros ficheiros já indexados.

## Soluções Implementadas

### 1. **Filtragem por Nome de Ficheiro**
```python
# ANTES (buscava em todos os documentos)
query_rag_documents("Qual foi a causa da morte?")

# AGORA (filtra apenas pelo documento específico)
query_rag_documents("Qual foi a causa da morte?", filename="caso_autopsia_forense.pdf")
```

### 2. **Validação de Documentos Indexados**
```python
# Nova função para verificar se um documento está indexado
def is_document_indexed(filename: str) -> bool:
    """Verifica se um documento específico está indexado."""
    try:
        col = _chroma_collection()
        result = col.get(where={"filename": {"$eq": filename}}, limit=1, include=[])
        return len(result["ids"]) > 0
    except Exception:
        return False
```

### 3. **Lista de Documentos Disponíveis**
```python
# Nova ferramenta para listar documentos indexados
@tool
def list_indexed_documents() -> str:
    """Lista todos os PDFs indexados e disponíveis para consulta."""
    # Implementação... 
```

### 4. **Filtragem no ChromaDB**
```python
# Adicionado filtro de metadados nas consultas
if filename:
    docs_with_scores = vs.similarity_search_with_score(
        query,
        k=top_k,
        filter={"filename": {"$eq": filename}}
    )
```

## Principais Alterações

### `rag/retriever.py`
- Função `retrieve()` agora aceita parâmetro opcional `filename`
- Filtro de metadados aplicado quando `filename` é especificado
- `get_retriever()` atualizado para suportar filtros

### `rag/generator.py` 
- Função `answer_with_rag()` agora aceita parâmetro `filename`
- Validação de documentos antes de fazer a busca
- Mensagens informativas quando documento não está disponível

### `rag/indexer.py`
- Nova função `is_document_indexed()` para validação
- Metadados de filename já eram guardados corretamente

### `agent/main.py`
- Tool `query_rag_documents()` atualizado com parâmetro `filename`
- Nova tool `list_indexed_documents()` 
- Instruções atualizadas para uso correto do filtering
- Validação automática de documentos indexados

## Exemplos de Uso

### Consulta Específica (Recomendado)
```python
# Pergunta sobre documento específico - sem contaminação
query_rag_documents(
    "Qual foi a causa da morte?", 
    filename="caso_autopsia_forense.pdf"
)
```

### Consulta Geral (Quando Apropriado)
```python
# Busca em todos os documentos indexados
query_rag_documents("Qual foi a causa da morte?")
```

### Verificar Documentos Disponíveis
```python
# Lista todos os documentos indexados
list_indexed_documents()
```

## Benefícios

1. **✅ Eliminação de Contaminação**: Resultados são filtrados por documento específico
2. **✅ Mensagens Claras**: Informa quando documento não está indexado
3. **✅ Escalabilidade**: Sistema funciona bem com múltiplos documentos
4. **✅ Compatibilidade**: Mantém funcionalidade original (busca global ainda disponível)
5. **✅ Validação Automática**: Verifica automaticamente se documento está disponível

## Fluxo de Trabalho Recomendado

1. **Listar documentos disponíveis**:
   ```python
   list_indexed_documents()
   ```

2. **Indexar novo documento** (se necessário):
   ```python
   ingest_pdf_document("novo_relatorio.pdf")
   ```

3. **Fazer consulta específica**:
   ```python
   query_rag_documents("pergunta", filename="novo_relatorio.pdf")
   ```

4. **Fazer consulta geral** (apenas quando apropriado):
   ```python
   query_rag_documents("pergunta comparativa entre documentos")
   ```

## Tratamento de Erros

- **Documento não indexado**: Mensagem clara orientando para indexar primeiro
- **Documento não encontrado**: Retorna informação específica sobre disponibilidade
- **Sem resultados**: Distingue entre documento não disponível vs. sem conteúdo relevante