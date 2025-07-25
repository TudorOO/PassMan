#Docker instructions

FROM python
WORKDIR /PassMan
COPY requirements.txt .


RUN pip install -r requirements.txt

COPY . .

ENV FLASK_APP=main.py

EXPOSE 8000

CMD ["python3", "./main.py"]