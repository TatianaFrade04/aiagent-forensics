# Build script for AIAgentForensics Docker image

$IMAGE_NAME = "forensics"
$TAG = "latest"
$DOCKERFILE = "docker\Dockerfile"

Write-Host "Building Docker image: ${IMAGE_NAME}:${TAG}" -ForegroundColor Cyan

docker build -t "${IMAGE_NAME}:${TAG}" -f $DOCKERFILE .\docker\

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful: ${IMAGE_NAME}:${TAG}" -ForegroundColor Green
} else {
    Write-Host "Build failed." -ForegroundColor Red
    exit 1
}
