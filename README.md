# Flask API with user authentication and token use

  Additionally it has another table to show and test logging permissions. The API is working with PostgreSQL, also if you want to it works with SQLite.

## Initial set up

* Python 3.8
* Pipenv

## To make it work

* Run on terminal

```
pipenv shell
pipenv sync
```

* Create an application.yml file

```
general:
	secret_key: your_secret_encription_key

development:
	user: postgres_user
	password: dope_password
	host: "localhost"
	port: "5432"
	database: database_used
  
production:
	user: production_user
	password: production_passwprd
	host: production_url
	port: postgres_port
	database: production_database
```

* Finally create the needed tables

```
python
```

* On python console

```
from app import db
db.create_all()
```

And you are good to go.