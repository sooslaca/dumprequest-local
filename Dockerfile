FROM python:alpine3.18

ENV PIP_ROOT_USER_ACTION=ignore
ENV PYTHONUNBUFFERED 1

COPY assets/ /

RUN pip list --outdated --format=columns 2>/dev/null | tail -n +3 | cut -f1 -d' ' | xargs -n1 pip install -U || true \
 && pip install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
CMD [ "/usr/local/bin/python", "/app/dumprequest.py" ]
