## Requirements 
* Python >=3.8
* requirements.txt

## Setup:
1. pip install -r requirements.txt
2. set FLASK_APP=project
3. python init_database.py
4. flask run --cert=assets/cert.crt --key=assets/cert.key password is "OchronaDanych2022" (or if any problems: flask run --cert=adhoc)

## Components:
* Flask - blueprints
* Flask-login
* Flask-sqlalchemy + SQLite

## Database scheme:
![image](https://user-images.githubusercontent.com/41429556/161428153-63300ccb-573d-4f25-9806-4465077585f8.png)

## Encrypted notes implementation scheme:
![image](https://user-images.githubusercontent.com/41429556/161428201-fd0fa0f7-3c54-470c-b3a3-5c7f1fea7590.png)

## Known issues:
* There should be a docker container prepared with certificates generated
* Javascript can be inserted onto a page via Markdown fields (as part of Markdown syntax)
