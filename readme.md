Projekt był tworzony na Windowsie, lista kroków do uruchomienia (wymagany Python >=3.8):
Przygotowałam środowisko wirtualne na Windowsie notes_app_venv, w którym zainstalowane są potrzebne paczki

Odtworzenie setupu:
1. pip install -r requirements.txt
2. set FLASK_APP=project
3. python init_database.py
4. flask run --cert=assets/cert.crt --key=assets/cert.key hasło to "OchronaDanych2022" (w razie problemów flask run --cert=adhoc)