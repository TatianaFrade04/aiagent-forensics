#!/usr/bin/env python3
"""
Script de teste para validar a correção do sistema RAG.
Testa a eliminação de contaminação entre documentos.
"""

import os
import sys

# Adicionar o directório rag ao path
sys.path.append(os.path.join(os.path.dirname(__file__), 'rag'))

def test_rag_system():
    """Testa o sistema RAG corrigido."""
    
    print("🧪 Teste do Sistema RAG - Correção de Contaminação")
    print("=" * 60)
    
    try:
        # Importar funções necessárias
        from rag.indexer import list_indexed_documents, is_document_indexed
        from rag.generator import answer_with_rag
        
        # 1. Listar documentos indexados
        print("\n1️⃣ Documentos atualmente indexados:")
        docs = list_indexed_documents()
        if not docs:
            print("   ❌ Nenhum documento indexado.")
            print("   💡 Use ingest_pdf_document() para indexar PDFs primeiro.")
            return
            
        for doc in docs:
            print(f"   📄 {doc['filename']} (ID: {doc['doc_id']})")
        
        # 2. Testar consulta específica por documento
        if len(docs) >= 2:
            print("\n2️⃣ Teste de consulta específica (sem contaminação):")
            
            # Pegar o primeiro documento
            first_doc = docs[0]['filename']
            print(f"   🎯 Consultando apenas: {first_doc}")
            
            # Fazer pergunta específica
            result = answer_with_rag(
                "Qual foi a causa da morte?", 
                filename=first_doc
            )
            
            print("   📝 Resposta:")
            print(f"      {result['answer'][:200]}...")
            
            print("   📚 Fontes utilizadas:")
            for source in result['sources']:
                print(f"      • {source['filename']} (página {source['page']})")
            
            # Verificar se só usou o documento pedido
            used_files = set(s['filename'] for s in result['sources'])
            if len(used_files) == 1 and first_doc in used_files:
                print("   ✅ SUCESSO: Apenas o documento pedido foi utilizado!")
            else:
                print("   ❌ FALHA: Contaminação detectada!")
                print(f"      Documentos usados: {used_files}")
        
        # 3. Testar validação de documento não indexado
        print("\n3️⃣ Teste de validação (documento inexistente):")
        fake_file = "documento_inexistente.pdf"
        
        if is_document_indexed(fake_file):
            print("   ❌ FALHA: Documento inexistente foi marcado como indexado!")
        else:
            print(f"   ✅ SUCESSO: '{fake_file}' corretamente identificado como não indexado")
        
        # Testar query de documento inexistente
        result = answer_with_rag("Pergunta qualquer", filename=fake_file)
        if "not indexed" in result['answer'] or "not found" in result['answer']:
            print("   ✅ SUCESSO: Mensagem apropriada para documento inexistente")
        else:
            print("   ❌ FALHA: Não retornou mensagem apropriada")
            print(f"      Resposta: {result['answer']}")
        
        # 4. Testar consulta geral (todos os documentos)
        print("\n4️⃣ Teste de consulta geral (todos os documentos):")
        result = answer_with_rag("Qual foi a causa da morte?")  # Sem filename
        
        used_files = set(s['filename'] for s in result['sources'])
        print(f"   📊 Documentos utilizados na busca geral: {used_files}")
        
        if len(used_files) > 1:
            print("   ✅ SUCESSO: Busca geral utilizou múltiplos documentos")
        else:
            print("   ℹ️  INFO: Busca geral utilizou apenas 1 documento")
        
        print("\n🎉 Todos os testes concluídos!")
        
    except ImportError as e:
        print(f"❌ Erro de importação: {e}")
        print("💡 Certifique-se de que o módulo RAG está configurado corretamente.")
    except Exception as e:
        print(f"❌ Erro durante os testes: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_rag_system()