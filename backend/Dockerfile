   # backend/Dockerfile
   FROM python:3.9-slim@sha256:d1fd807555208707ec95b284afd10048d0737e84b5f2d6fdcbed2922b9284b56

   WORKDIR /app

   COPY requirements.txt .

   RUN pip install --no-cache-dir --upgrade pip && \
       pip install --no-cache-dir -r requirements.txt && \
       pip list  # Print installed packages for debugging

   COPY . .

   EXPOSE 5000

   CMD ["python", "app.py"]