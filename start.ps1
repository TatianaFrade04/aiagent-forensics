# ── Configuração ──────────────────────────────────────────────────────────────
$IMAGE     = "forensics"   # imagem Docker a usar
$CONTAINER = "forensics"   # nome do container
$EVIDENCE  = "$PSScriptRoot\evidence"  # pasta com as evidências
# ── Fim configuração ───────────────────────────────────────────────────────────

# Remover container antigo se existir
$existing = docker ps -aq --filter "name=^${CONTAINER}$"
if ($existing) {
    Write-Host "A remover container antigo '$CONTAINER'..."
    docker rm -f $existing | Out-Null
}

# Arrancar container com a pasta evidence montada em /evidence (read-only)
Write-Host "A arrancar '$CONTAINER' com imagem '$IMAGE'..."
docker run -d --name $CONTAINER -v "${EVIDENCE}:/evidence:ro" $IMAGE
if ($LASTEXITCODE -ne 0) { Write-Error "Falha ao arrancar o container."; exit 1 }

Write-Host "Container pronto. A iniciar o agente...`n"
$env:FORENSICS_CONTAINER = $CONTAINER
py -m agent.llm_langchain
