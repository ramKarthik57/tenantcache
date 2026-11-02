FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt
COPY . .
ENV PYTHONPATH=/app
CMD ["uvicorn", "lab.application.main:app", "--host", "0.0.0.0", "--port", "8000"]
