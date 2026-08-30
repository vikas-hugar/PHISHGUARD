web: if [ -d "backend" ]; then cd backend; fi && gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 120
