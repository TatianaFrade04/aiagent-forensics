# Cábula de Testes — AIAgent@forensics
**Modelo:** `gemma4:e4b` · Temperatura: `0.0` · Contexto: `131072` · Limpeza entre perguntas: ativa

---

## Comando Base para Correr o Agente

```bash
uv run forensics --model gemma4:e4b --temp 0.3 --ctx 131072
```

> **Com limpeza de contexto entre perguntas** (recomendado para Teste 2):
> ```bash
> uv run forensics --model gemma4:e4b --temp 0.0 --ctx 131072 --clear-after-question
> ```

> Alternativa sem uv:
> ```bash
> python -m agent.main --model gemma4:e4b --temp 0.0 --ctx 131072
> ```

---

## TESTE 1 — Prompt Único Abrangente (Free-Form Investigation)

**Configuração:** sem `--clear-after-question` (sessão única, contexto acumulado)
**Objetivo:** avaliar a capacidade do agente de conduzir uma investigação forense autónoma e completa a partir de um briefing policial realista, sem perguntas guiadas.

### Prompt a enviar ao agente (colar quando ele pedir input):

```
The user of this forensic image is Jimmy Wilson, and he is currently under criminal investigation for illegal firearms smuggling and homicide. Law enforcement has seized his computer and you are the forensic investigator assigned to this case.

Your mission is to conduct a full digital forensic investigation of this evidence image and produce a comprehensive investigation report. Specifically, you must:

1. DISK AND SYSTEM OVERVIEW
   - Identify the disk partitioning schema (MBR/GPT) and the disk GUID
   - List all partitions, their GUIDs, sizes, and file system types
   - Identify the Windows version and system hostname

2. USER ACCOUNTS
   - List all user accounts present on the system (including full names, RIDs, and account status)
   - Identify which accounts are active, disabled, or guest accounts
   - Check if any accounts have password hints set

3. EMAIL COMMUNICATIONS
   - Locate and examine all email files (.eml) found on the system
   - For each email: extract sender, recipient, date/time (original sent time and received time), subject, body content, and routing headers (IP addresses in Received headers)
   - Identify any suspicious contacts or external email addresses

4. WEB ACTIVITY AND BROWSER HISTORY
   - Recover browser history and identify all websites visited
   - Look specifically for searches related to weapons, smuggling, illegal activities, identity theft, or money laundering
   - Identify the search engine(s) used and notable search queries

5. STARTUP PROGRAMS AND PERSISTENCE
   - Check the Windows registry Run keys for any programs configured to launch at startup
   - Identify any suspicious or unusual executables set to auto-run

6. ENCRYPTION AND DATA HIDING
   - Identify any encryption or data-hiding software installed or used (e.g. TrueCrypt, VeraCrypt, BCTextEncoder, BitLocker)
   - Note any evidence of data obfuscation or anti-forensic behaviour

7. RECYCLE BIN
   - List all files that were deleted and sent to the Recycle Bin
   - Identify which user account deleted each file and when

8. KEY FILES OF INTEREST
   - Locate and examine any PDF, TXT, HTM, or document files that may be relevant to the investigation
   - Compute SHA1/MD5 hashes for key files to establish integrity
   - If any files contain text content, summarise what they say

9. TIMELINE AND LAST ACTIVITY
   - Determine the last login date and time for the primary suspect (Jimmy Wilson)
   - Determine the last time key applications (e.g. Windows Mail) were used, using jump lists or registry data
   - Identify the system uptime at any known reference timestamp if recoverable

10. SUMMARY OF FINDINGS
    - At the end, produce a structured summary of ALL evidence found that is relevant to the firearms smuggling and homicide investigation
    - For each finding, state: WHAT was found, WHERE it was found (full path or registry key), and WHY it is forensically relevant
    - Highlight the most incriminating evidence first

Be thorough. Use all available forensic tools inside the container. Document every finding with its exact source location.
```

### O que avaliar nos resultados:
- Cobertura das 10 categorias acima sem ser guiado pergunta a pergunta
- Capacidade de sintetizar um relatório final estruturado
- Precisão dos dados encontrados (cruzar com ground truth do CTF)
- Número de tool calls geradas autonomamente

---

## TESTE 2 — Investigação Sequencial (First-Time Investigator)

**Configuração:** `--clear-after-question` ativo (contexto limpo entre cada pergunta)
**Objetivo:** simular um investigador que nunca viu a imagem e vai descobrindo a evidência progressivamente, como aconteceria numa investigação real. Cada pergunta é independente.

### Mapa de Investigação (Plano por Fases)

```
FASE 1 — Reconhecimento do Disco
   └─ Q1: Visão geral
   └─ Q2: Partições
   └─ Q3: Identificadores do disco

FASE 2 — Utilizadores e Contas
   └─ Q4: Listar utilizadores
   └─ Q5: Detalhes do utilizador principal

FASE 3 — Exploração de Ficheiros
   └─ Q6: Conteúdo da pasta do suspeito
   └─ Q7: Ficheiros suspeitos no desktop e documentos

FASE 4 — Comunicações
   └─ Q8: Emails encontrados
   └─ Q9: Análise de email específico

FASE 5 — Atividade Web
   └─ Q10: Histórico do browser

FASE 6 — Registo do Sistema
   └─ Q11: Programas a arrancar no login
   └─ Q12: Último login do suspeito

FASE 7 — Dados Eliminados e Cifrados
   └─ Q13: Recycle bin
   └─ Q14: Software de encriptação

FASE 8 — Síntese Final
   └─ Q15: Resumo de tudo o que foi descoberto
```

---

### Sequência de Perguntas (copiar e colar uma a uma)

> **IMPORTANTE:** Depois de o agente responder a cada pergunta, aguardar que o agente termine completamente (prompt volta a aparecer) antes de colar a próxima.

---

#### FASE 1 — Reconhecimento do Disco

**Q1 — Visão Geral:**
```
I am a digital forensic investigator and I have just received a forensic disk image to examine. I have never looked at this evidence before. Start by giving me a general overview of what is on this disk image: what type of disk it is, how it is partitioned, and what operating system is installed. Use any forensic tools available to you.
```

**Q2 — Partições:**
```
Now examine the partition table of this disk image in detail. List every partition found: its number, file system type, size in bytes, and any unique identifiers (GUIDs) associated with each partition. What partitioning schema is used — MBR or GPT?
```

**Q3 — Identificadores do Disco:**
```
What is the unique disk GUID of this physical disk? Provide it in hexadecimal format. Also confirm the cluster size in bytes of the main Windows partition.
```

---

#### FASE 2 — Utilizadores e Contas

**Q4 — Listar Utilizadores:**
```
How many user accounts exist on this Windows system? List all of them with their full names, usernames, and RID numbers. Also indicate which accounts are active and which are disabled.
```

**Q5 — Detalhes do Utilizador Principal:**
```
Focus on the user account "Jimmy Wilson". Is his Windows logon password enabled? Does he have a password hint set, and if so, what is it? What is his last recorded login date and time?
```

---

#### FASE 3 — Exploração de Ficheiros

**Q6 — Conteúdo da Pasta do Suspeito:**
```
I want to explore the files belonging to the user Jimmy Wilson. List the contents of his home directory (C:\Users\Jimmy Wilson or equivalent). What folders and files exist there? Are there any unusual or suspicious items?
```

**Q7 — Ficheiros Suspeitos:**
```
Search the entire Windows partition for any PDF, TXT, HTM, and document files that might be relevant to a criminal investigation. List their names, full paths, and file sizes in bytes. For any text files found, show me their contents.
```

---

#### FASE 4 — Comunicações por Email

**Q8 — Emails Encontrados:**
```
Search for all email files (.eml) on this system. List every email file found, including its location, file name, sender address, recipient address, and the date and time the email was originally sent. Who sent emails to Jimmy Wilson?
```

**Q9 — Análise do Email Principal:**
```
Examine the email file "447018D5-00000006.eml" in detail. I need the following information:
- The exact date and time the email was originally sent (from the Date header)
- The sender's email address
- The destination time zone offset in the first Received header
- The final destination IP address listed in the Received headers
Show me the raw headers of this email.
```

---

#### FASE 5 — Atividade Web

**Q10 — Histórico do Browser:**
```
Recover the web browsing history for the user Jimmy Wilson. What websites did he visit? Were any searches performed? If so, what were the search queries and which search engine was used? I am particularly interested in any searches related to illegal activities.
```

---

#### FASE 6 — Registo do Sistema

**Q11 — Programas no Arranque:**
```
Check the Windows registry Run keys (HKLM and HKCU) for any programs configured to launch automatically when the user logs in. What executables are listed? Are any of them unusual or suspicious?
```

**Q12 — Última Actividade de Aplicações:**
```
Using Windows jump lists or registry data, determine the last date and time that the Windows Mail application was run by Jimmy Wilson. Also check the system uptime recorded for this machine.
```

---

#### FASE 7 — Dados Eliminados e Cifrados

**Q13 — Recycle Bin:**
```
Examine the Windows Recycle Bin ($Recycle.Bin) on this system. What files were deleted and placed in the Recycle Bin? For each file: provide the original filename, the original path, the size, the deletion date and time, and which user account deleted it.
```

**Q14 — Software de Encriptação:**
```
Search this Windows system for any encryption or data-hiding software. Look for installed programs, executable files, and registry entries related to tools like TrueCrypt, VeraCrypt, BCTextEncoder, BitLocker, or similar. What encryption tools were used on this computer?
```

---

#### FASE 8 — Síntese Final

**Q15 — Resumo Forense Completo:**
```
Based on all the forensic investigation performed on this disk image, produce a final structured summary of all significant findings. For each finding, state:
1. WHAT was found
2. WHERE it was found (exact file path or registry key)
3. WHY it is forensically significant

Organise the findings by category: disk metadata, user accounts, email communications, web activity, suspicious programs, deleted files, and encryption tools. Conclude with an overall assessment of what the digital evidence reveals about the activities of the user Jimmy Wilson.
```

---

## Referência Rápida — Ground Truth das Respostas CTF

| # | Tópico | Resposta correta |
|---|--------|-----------------|
| Q1 | Time zone offset no 1º Received header do .eml | `-08:00` |
| Q2 | Capacidade da partição "J. Wilson" = 734,003,200 bytes | **true** |
| Q3 | Data/hora de envio do 447018D5 eml | Sun, 16 Feb 2014 **12:55:09** -05:00 |
| Q4 | Disk GUID = 6FAE8D386C441743AE3298C4BDE04830 | **true** |
| Q5 | Cluster size da 2ª partição = 512 bytes | **false** |
| Q6 | Uptime em 20/02/2014 17:02:35 UTC = 9,634 s | **true** |
| Q8 | Password enabled + hint = "safeone" | **true** |
| Q9 | Partitioning schema | **GPT** |
| Q10 | IP final do email = 10.221.48.196 | **true** |
| Q13 | BillyBob enviou "New Price List.txt" para Recycle Bin | **false** |
| Q15 | User com RID 0x3EB | **Joe T. Nameless** |
| Q16 | Último login Jimmy Wilson | **d) Nenhuma das anteriores** (nenhuma opção é correta) |
| Q17 | Emails de jose.Badguy@hushmail.com e robert.ripoff@gmx.com | **true** |
| Q18 | Programa no arranque | **StinkyNot.exe** |
| Q20 | Programas de encriptação | **TrueCrypt/BCTextEncoder** |
| Q23 | Motor de busca para "how to steal identities" | **Bing** |
| Q24 | Último uso do Windows Mail | Sat, 25 Jan 2014 **18:27:51** UTC |

---

## Notas para o Relatório

- **Teste 1** avalia raciocínio autónomo: o agente recebe um briefing e decide sozinho o que investigar
- **Teste 2** avalia granularidade e precisão: cada pergunta é isolada (sem contexto anterior), testando se o agente consegue responder a uma única questão forense sem memória acumulada
- A combinação `temp=0.0 + limpeza de contexto` elimina variabilidade estocástica — respostas são determinísticas e comparáveis entre runs
- Documentar no relatório: número de tool calls por pergunta, tempo de resposta, e se o agente precisou de retries/corrected itself
