$IMAGE_NAME = "forensics-sandbox"
$TAG = "latest"

Write-Host "A fazer build da imagem Docker..." -ForegroundColor Cyan

docker build -t "${IMAGE_NAME}:${TAG}" -f docker\Dockerle .\docker\

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build concluido com sucesso: ${IMAGE_NAME}:${TAG}" -ForegroundColor Green
} else {
    Write-Host "Erro no build da imagem" -ForegroundColor Red
    exit 1
}
