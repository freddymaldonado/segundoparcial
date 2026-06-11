FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY samples/ samples/
COPY web/ web/

ENV WEB_HOST=0.0.0.0 AUTO_OPEN=0
EXPOSE 8000

CMD ["python", "src/webapp.py"]
