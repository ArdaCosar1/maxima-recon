# plugins/ — Kullanıcı tanımlı Maxima modülleri
# Bu dizine .py dosyaları bırakarak kendi tarama modüllerinizi ekleyebilirsiniz.
#
# Örnek plugin:
#
#   from utils.base_module import BaseModule, ModuleResult
#
#   class MyCustomScanner(BaseModule):
#       """Benim özel tarayıcım"""
#       def run(self) -> ModuleResult:
#           resp = self.http_get(self.url)
#           if "secret" in resp.get("body", ""):
#               self.add_finding("Gizli Bilgi", "Detay...", "high")
#           return self.results
#
# Plugin'ler otomatik olarak keşfedilir ve menüye eklenir.
