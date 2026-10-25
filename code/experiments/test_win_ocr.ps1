Add-Type -AssemblyName System.Drawing
[Windows.Media.Ocr.OcrEngine, Windows.Foundation.UniversalApiContract, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation.UniversalApiContract, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Foundation.UniversalApiContract, ContentType = WindowsRuntime] | Out-Null

$imagePath = (Resolve-Path "dataset\evidence\images\account_admin_console_20260926.png").Path

function Get-OcrText($filePath) {
    $asyncOp = [Windows.Storage.StorageFile]::GetFileFromPathAsync($filePath)
    $file = $asyncOp.GetAwaiter().GetResult()
    $streamAsync = $file.OpenAsync([Windows.Storage.FileAccessMode]::Read)
    $stream = $streamAsync.GetAwaiter().GetResult()
    $decoderAsync = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)
    $decoder = $decoderAsync.GetAwaiter().GetResult()
    $bitmapAsync = $decoder.GetSoftwareBitmapAsync()
    $bitmap = $bitmapAsync.GetAwaiter().GetResult()
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    $ocrResultAsync = $engine.RecognizeAsync($bitmap)
    $ocrResult = $ocrResultAsync.GetAwaiter().GetResult()
    return $ocrResult.Text
}

$text = Get-OcrText $imagePath
Write-Output "OCR Result length: $($text.Length)"
Write-Output $text
