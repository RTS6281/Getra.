FROM python:3.9
WORKDIR /code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["gunicorn", "-b", "0.0.0.0:7860", "app:app"]
