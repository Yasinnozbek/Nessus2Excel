# Nessus Report Parser

Bu Python script'i, `.nessus` uzantılı XML rapor dosyalarını okuyarak, zafiyetleri gruplayan, renklendirilmiş ve detaylı bir Excel rapor çıktısı oluşturur. v2 script'i ise daha az veri ile bir Excel rapor çıktısı oluşturur.

Not: Yalnızca Severity 1 ve üzeri zafiyetler Excel rapor çıktısına eklenir.
---

## 📦 Gereksinimler

- Python 3.6 veya üzeri
- Aşağıdaki Python kütüphaneleri:

```bash
pip install -r requirements.txt
```

## Kullanım
```bash
./n2e.py path/to/file.nessus -o output.xlsx
```
