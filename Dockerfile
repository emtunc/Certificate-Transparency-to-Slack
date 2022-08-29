FROM python:3.10

WORKDIR /src

COPY requirements.txt /src
RUN pip install -r /src/requirements.txt
COPY ct-alerts-to-slack.py /src

ENTRYPOINT ["python3", "/src/ct-alerts-to-slack.py"]
