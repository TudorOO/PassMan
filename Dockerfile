#Docker instructions

FROM python
WORKDIR /PassMan
COPY requirements.txt .


RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "./server.py"]