FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY detector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the detector package as a subdirectory so imports work:
#   from detector.audit_log import AuditLog  ← finds /app/detector/audit_log.py
COPY detector/ ./detector/

# Copy the entry point (main.py lives inside detector/ but is the daemon entry)
# We run it as a module so Python resolves the package correctly
CMD ["python", "-m", "detector.main"]
