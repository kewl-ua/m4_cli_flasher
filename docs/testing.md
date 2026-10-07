[← README](../README.md)

# Тесты

```powershell
$env:PYTHONPATH = "."
py -m unittest discover -s tests -p "test_*.py"
```

353 теста, без USB и без дрона. Три сверки с захватом включаются, если
указать пакет и захват его прошивки:

```powershell
$env:DJI_DUML_PACKAGE = "C:\dev\fw_list\m4t\M4T_UAV_17.02.05.01_pro.zip"
$env:DJI_DUML_CAPTURE = "C:\dev\captures\offline_usb.pcap"
py -m unittest discover -s tests -p "test_duml_assistant_parity.py"
py -m unittest discover -s tests -p "test_duml_extract.py"
```

Хранилище на настоящих файлах (каждая проверка — своя переменная; файлы
только читаются, хранилище — во временной папке):

```powershell
$env:DJI_DUML_FW_DIR = "C:\dev\fw_list\m4t"         # три версии готовы; экспорт 14.01.0012 = b23b8d43…
$env:DJI_DUML_FIRM_CACHE = "C:\Program Files (x86)\DJI Product\DJI Assistant 2 (Enterprise Series)\DJIEngine\DJIData\firm_cache"
$env:DJI_DUML_STORE_CAPTURE = "C:\dev\captures\upgrade_17_usb.pcap"
py -m unittest discover -s tests -p "test_duml_ingest.py"
```

По захвату подключения Assistant, для `manifest` и `params`:

```powershell
$env:DJI_DUML_IDLE_CAPTURE = "C:\dev\captures\idle.pcap"
py -m unittest discover -s tests -p "test_duml_readers.py"
```
