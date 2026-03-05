# Projeto informático n.º (5)
# AIAgent@forensics

**Instituição:** Politécnico de Leiria – Escola Superior de Tecnologia e Gestão  
**Curso:** Licenciatura em Engenharia Informática  

**Ano Letivo:** 2025–2026  

---

# Área Temática

- **IA** – Inteligência Artificial  
- **IF** – Informática Forense  

---

# Descrição

Este projeto propõe-se investigar de que forma **modelos de linguagem de grande escala (LLMs)** podem apoiar tarefas de investigação forense digital, através de **agentes capazes de raciocinar e agir com acesso a ferramentas de linha de comando**, seguindo o paradigma **ReAct (Reason + Act)**.

No âmbito de uma investigação forense é habitual encontrar **vastas quantidades de dados**, sendo que os ficheiros ou partes de ficheiros de interesse podem ser apenas uma **pequena fração do total**.

Através de ferramentas de linha de comando em ambiente **Linux**, é possível encontrar e extrair informações relevantes.

Exemplos:

- O comando **`find`** permite procurar ficheiros por padrões no nome do ficheiro ou datas de modificação.
- O comando **`grep`** permite procurar padrões de texto no conteúdo dos ficheiros.

A proposta centra-se na avaliação de uma abordagem em que um **LLM, orientado por instruções do utilizador**, explora autonomamente uma **imagem forense em modo de leitura**, selecionando e executando comandos adequados para localizar **prova potencialmente relevante**.

---

# Objetivos

- Avaliar a eficácia de um **agente LLM** na descoberta e extração de informação pertinente em cenários de investigação forense.
- Desenvolver uma ferramenta do tipo **chatbot** que permita ao utilizador dirigir a investigação (definir hipóteses, prioridades e constrangimentos) enquanto o agente executa tarefas técnicas.
- Garantir a execução em **ambiente controlado**, recorrendo a uma **sandbox** para mitigar riscos e preservar o sistema do investigador.

---

# Abordagem técnica

- Implementação em **Python**, com recurso a bibliotecas de orquestração de agentes (ex.: **LangChain**).
- Execução de comandos dentro de um **container Docker** para isolar o ambiente e controlar permissões.
- Acesso a uma **cópia forense (imagem forense)** em modo **read-only**, garantindo a integridade da prova.

---

# Módulos

## Módulo 1

**Título:** AIAgent@forensics

---

# Competências necessárias

- Programação em **Python**

---

# Requisitos

- **Computador próprio**

---

# Orientadores

- **Miguel Negrão**  
  miguel.negrao@ipleiria.pt  

- **Miguel Frade**  
  miguel.frade@ipleiria.pt  

- **Patrício Domingues**  
  patricio.domingues@ipleiria.pt
