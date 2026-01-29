# This build script requires LLVM and Clang to be installed and available on the system PATH
# Download from: https://github.com/llvm/llvm-project/releases/

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputDir = Join-Path $projectRoot "bin"
$outputExe = Join-Path $outputDir "vmcall_test.exe"

# Create output directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Assemble .asm file with llvm-cl
Write-Host "Assembling .asm files..." -ForegroundColor Cyan
llvm-ml -m64 /c vmcall.asm /Fo "$outputDir\vmcall.obj"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Assembly failed" -ForegroundColor Red
    exit 1
}

# Build with clang
Write-Host "Building with Clang..." -ForegroundColor Cyan
clang -o $outputExe "$outputDir\*.obj" *.c
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful: $outputExe" -ForegroundColor Green